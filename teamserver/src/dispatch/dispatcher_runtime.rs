use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

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
    // Refresh liveness on every GET_JOB poll.  Each incoming DEMON_COMMAND_GET_JOB
    // proves the agent is alive; without this update `last_call_in` is only set at
    // DEMON_INIT registration and the liveness monitor marks agents dead after
    // `sleep_delay * 3` seconds even when they are actively polling (sc08 root cause).
    // The ECDH path does the same thing in listeners/http/ecdh_dispatch/session.rs.
    match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(ts) => {
            if let Err(e) = registry.set_last_call_in(agent_id, ts).await {
                warn!(
                    agent_id = format_args!("{agent_id:08X}"),
                    "GET_JOB liveness refresh: set_last_call_in failed — \
                     agent is alive but last_call_in is stale: {e}"
                );
            }
        }
        Err(e) => {
            warn!(
                agent_id = format_args!("{agent_id:08X}"),
                "GET_JOB liveness refresh: timestamp format failed — \
                 set_last_call_in skipped: {e}"
            );
        }
    }

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

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::*;
    use crate::{AgentRegistry, Database};

    const AGENT_ID: u32 = 0xDEAD_C0DE;

    fn sample_agent() -> red_cell_common::AgentRecord {
        red_cell_common::AgentRecord {
            agent_id: AGENT_ID,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: Zeroizing::new(vec![0u8; 32]),
                aes_iv: Zeroizing::new(vec![0u8; 16]),
                monotonic_ctr: false,
            },
            hostname: "test-host".to_owned(),
            username: "test-user".to_owned(),
            domain_name: "test".to_owned(),
            external_ip: "127.0.0.1".to_owned(),
            internal_ip: "10.0.0.1".to_owned(),
            process_name: "test.exe".to_owned(),
            process_path: "C:\\test.exe".to_owned(),
            base_address: 0x1000,
            process_pid: 100,
            process_tid: 101,
            process_ppid: 1,
            process_arch: "x64".to_owned(),
            elevated: false,
            os_version: "Windows 10".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 1,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-01-01T00:00:00Z".to_owned(),
            last_call_in: "2026-01-01T00:00:00Z".to_owned(),
            archon_magic: None,
        }
    }

    async fn setup() -> (AgentRegistry, Database) {
        let db = Database::connect_in_memory().await.expect("in-memory db");
        let registry = AgentRegistry::new(db.clone());
        registry.insert(sample_agent()).await.expect("insert sample agent");
        (registry, db)
    }

    /// GET_JOB must advance `last_call_in` so the liveness monitor does not mark
    /// the agent dead between polls (sc08 root cause: Sleep=1s → timeout=3s).
    #[tokio::test]
    async fn get_job_refreshes_last_call_in() {
        let (registry, _db) = setup().await;

        let before = registry
            .get(AGENT_ID)
            .await
            .expect("agent must exist")
            .last_call_in
            .clone();

        // Small delay so that `now_utc()` inside handle_get_job is guaranteed to be
        // strictly later than the seeded timestamp.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        handle_get_job(&registry, AGENT_ID, 0x01).await.expect("handle_get_job must succeed");

        let after = registry
            .get(AGENT_ID)
            .await
            .expect("agent must exist")
            .last_call_in
            .clone();

        assert_ne!(
            before, after,
            "handle_get_job must update last_call_in to keep the liveness monitor from \
             marking an actively-polling agent dead"
        );
        assert!(
            after > before,
            "updated last_call_in ({after}) must be strictly later than the initial \
             value ({before})"
        );
    }

    /// GET_JOB on an unknown agent must not panic — it should propagate the error
    /// from `set_last_call_in` gracefully (warns and continues) then fail when
    /// `dequeue_jobs` also cannot find the agent.
    #[tokio::test]
    async fn get_job_unknown_agent_returns_error() {
        let (registry, _db) = setup().await;
        let result = handle_get_job(&registry, 0xFFFF_FFFF, 0x01).await;
        assert!(result.is_err(), "unknown agent must return an error from dequeue_jobs");
    }
}
