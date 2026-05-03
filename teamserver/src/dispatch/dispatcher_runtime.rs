use red_cell_common::demon::{DemonCommand, DemonMessage, DemonPackage};

use super::{AgentRegistry, CommandDispatchError, CommandDispatcher, DemonCallbackPackage};
use crate::TeamserverError;

impl CommandDispatcher {
    /// Dispatch a single parsed callback package.
    #[tracing::instrument(skip(self, payload), fields(agent_id = format_args!("0x{:08X}", agent_id), command_id = format_args!("0x{:04X}", command_id), request_id))]
    pub async fn dispatch(
        &self,
        agent_id: u32,
        command_id: u32,
        request_id: u32,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, CommandDispatchError> {
        let Some(handler) = self.handlers.get(&command_id).cloned() else {
            return Err(CommandDispatchError::UnknownCommand { agent_id, command_id, request_id });
        };

        let cmd_label = format!("0x{command_id:04X}");
        crate::metrics::inc_callbacks_total(&cmd_label);
        let start = std::time::Instant::now();
        let result = handler(agent_id, request_id, payload.to_vec()).await;
        crate::metrics::observe_callback_latency(&cmd_label, start.elapsed().as_secs_f64());
        result
    }

    /// Dispatch multiple parsed callback packages and concatenate any response packages.
    #[tracing::instrument(skip(self, packages), fields(agent_id = format_args!("0x{:08X}", agent_id), package_count = packages.len()))]
    pub(crate) async fn dispatch_packages(
        &self,
        agent_id: u32,
        packages: &[DemonCallbackPackage],
        endian: super::PayloadEndian,
    ) -> Result<Vec<u8>, CommandDispatchError> {
        super::PAYLOAD_ENDIAN.scope(endian, self.collect_response_bytes(agent_id, packages)).await
    }

    pub(in crate::dispatch) async fn collect_response_bytes(
        &self,
        agent_id: u32,
        packages: &[DemonCallbackPackage],
    ) -> Result<Vec<u8>, CommandDispatchError> {
        let mut response = Vec::new();

        for package in packages {
            match self
                .dispatch(agent_id, package.command_id, package.request_id, &package.payload)
                .await
            {
                Ok(Some(bytes)) => response.extend_from_slice(&bytes),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        agent_id = format_args!("0x{agent_id:08X}"),
                        command_id = format_args!("0x{:04X}", package.command_id),
                        request_id = format_args!("0x{:08X}", package.request_id),
                        %error,
                        "callback handler failed; continuing remaining packages"
                    );
                }
            }
        }

        Ok(response)
    }
}

pub(in crate::dispatch) async fn handle_get_job(
    registry: &AgentRegistry,
    agent_id: u32,
    request_id: u32,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let jobs = registry.dequeue_jobs(agent_id).await?;
    if jobs.is_empty() {
        // Send DEMON_COMMAND_NO_JOB so the Demon agent's CommandDispatcher loop
        // keeps running and calls JobCheckList() to drain piped-process output.
        // An empty HTTP body causes the Demon to break out of CommandDispatcher
        // (treating it as a transport failure) before JobCheckList is reached,
        // leaving piped output queued forever and causing task timeouts.
        let no_job = DemonPackage::new(DemonCommand::CommandNoJob, request_id, Vec::new());
        return Ok(Some(no_job.to_bytes().map_err(TeamserverError::from)?));
    }

    // ECDH agents have no AES session key; the outer AES-256-GCM seal in
    // `process_ecdh_session` already provides confidentiality.
    let skip_aes = registry.is_ecdh_transport(agent_id).await;

    let mut packages = Vec::with_capacity(jobs.len());

    for job in jobs {
        let payload = if job.payload.is_empty() || skip_aes {
            job.payload
        } else {
            registry.encrypt_for_agent(agent_id, &job.payload).await?
        };
        packages.push(DemonPackage {
            command_id: job.command,
            request_id: job.request_id,
            payload,
        });
    }

    Ok(Some(DemonMessage::new(packages).to_bytes()?))
}
