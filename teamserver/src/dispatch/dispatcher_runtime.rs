use red_cell_common::demon::{DemonMessage, DemonPackage};

use super::{AgentRegistry, CommandDispatchError, CommandDispatcher, DemonCallbackPackage};

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
    pub async fn dispatch_packages(
        &self,
        agent_id: u32,
        packages: &[DemonCallbackPackage],
    ) -> Result<Vec<u8>, CommandDispatchError> {
        self.collect_response_bytes(agent_id, packages).await
    }

    pub(in crate::dispatch) async fn collect_response_bytes(
        &self,
        agent_id: u32,
        packages: &[DemonCallbackPackage],
    ) -> Result<Vec<u8>, CommandDispatchError> {
        let mut response = Vec::new();

        for package in packages {
            if let Some(bytes) = self
                .dispatch(agent_id, package.command_id, package.request_id, &package.payload)
                .await?
            {
                response.extend_from_slice(&bytes);
            }
        }

        Ok(response)
    }
}

pub(in crate::dispatch) async fn handle_get_job(
    registry: &AgentRegistry,
    agent_id: u32,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let jobs = registry.dequeue_jobs(agent_id).await?;
    if jobs.is_empty() {
        return Ok(None);
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
