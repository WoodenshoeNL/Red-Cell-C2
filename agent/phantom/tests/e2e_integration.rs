//! End-to-end integration tests for the Phantom agent.
//!
//! These tests spin up a mock teamserver (raw HTTP + Demon protocol) and drive
//! the Phantom agent through a complete lifecycle: init handshake, checkins,
//! shell command, filesystem ops, process listing, network enumeration, and exit.
//!
//! Run with: `cargo test --package phantom` (or `cargo nextest run --package phantom`)

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
    encrypt_agent_data, encrypt_agent_data_at_offset,
};
use red_cell_common::demon::{
    DemonCommand, DemonEnvelope, DemonFilesystemCommand, DemonMessage, DemonNetCommand,
    DemonPackage, DemonProcessCommand,
};

use phantom::PhantomAgent;
use phantom::config::PhantomConfig;

// ---------------------------------------------------------------------------
// Mock teamserver helpers
// ---------------------------------------------------------------------------

/// State tracked by the mock teamserver side.
struct MockCrypto {
    agent_id: u32,
    key: Vec<u8>,
    iv: Vec<u8>,
    /// Shared monotonic CTR block offset, mirroring the teamserver's single offset.
    ctr_offset: u64,
}

impl MockCrypto {
    /// Extract crypto material from a DEMON_INIT packet body.
    fn from_init_body(body: &[u8]) -> Self {
        let envelope = DemonEnvelope::from_bytes(body).expect("parse init envelope");
        let agent_id = envelope.header.agent_id;
        // payload layout: [command_id:4][request_id:4][raw_key:32][raw_iv:16][encrypted_metadata...]
        let key = envelope.payload[8..8 + AGENT_KEY_LENGTH].to_vec();
        let iv =
            envelope.payload[8 + AGENT_KEY_LENGTH..8 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH].to_vec();
        Self { agent_id, key, iv, ctr_offset: 0 }
    }

    /// Build the encrypted init acknowledgement.
    fn build_init_ack(&mut self) -> Vec<u8> {
        let ack = encrypt_agent_data(&self.key, &self.iv, &self.agent_id.to_le_bytes())
            .expect("encrypt init ack");
        self.ctr_offset = ctr_blocks_for_len(ack.len());
        ack
    }

    /// Build the raw [`DemonMessage`] bytes returned by `handle_get_job`.
    ///
    /// Each package payload is individually encrypted at successive monotonic
    /// CTR offsets, mirroring what the teamserver's `encrypt_for_agent` does.
    /// `self.ctr_offset` is advanced past each encrypted payload.
    fn build_get_job_response(&mut self, packages: Vec<DemonPackage>) -> Vec<u8> {
        if packages.is_empty() {
            return Vec::new();
        }
        let mut enc_packages = Vec::with_capacity(packages.len());
        for package in packages {
            let encrypted_payload = if package.payload.is_empty() {
                Vec::new()
            } else {
                let enc = encrypt_agent_data_at_offset(
                    &self.key,
                    &self.iv,
                    self.ctr_offset,
                    &package.payload,
                )
                .expect("encrypt job payload");
                self.ctr_offset += ctr_blocks_for_len(enc.len());
                enc
            };
            enc_packages.push(DemonPackage {
                command_id: package.command_id,
                request_id: package.request_id,
                payload: encrypted_payload,
            });
        }
        DemonMessage::new(enc_packages).to_bytes().expect("serialize get_job response")
    }

    /// Decrypt a COMMAND_CHECKIN packet.
    fn decrypt_checkin(&mut self, body: &[u8]) -> (u32, u32, Vec<u8>) {
        let (cmd, req, payload) = self.decrypt_callback(body);
        assert_eq!(cmd, u32::from(DemonCommand::CommandCheckin), "expected CommandCheckin");
        (cmd, req, payload)
    }

    /// Decrypt a COMMAND_GET_JOB packet.
    fn decrypt_get_job(&mut self, body: &[u8]) -> (u32, u32, Vec<u8>) {
        let (cmd, req, payload) = self.decrypt_callback(body);
        assert_eq!(cmd, u32::from(DemonCommand::CommandGetJob), "expected CommandGetJob");
        (cmd, req, payload)
    }

    /// Decrypt a callback packet.
    ///
    /// Wire format: `command_id(4, clear) | request_id(4, clear) | encrypted(seq_num(8 LE) | payload_len(4 BE) | payload)`.
    fn decrypt_callback(&mut self, body: &[u8]) -> (u32, u32, Vec<u8>) {
        let envelope = DemonEnvelope::from_bytes(body).expect("parse envelope");
        assert_eq!(envelope.header.agent_id, self.agent_id);

        // command_id and request_id are in the clear.
        let command_id =
            u32::from_be_bytes(envelope.payload[0..4].try_into().expect("command_id bytes"));
        let request_id =
            u32::from_be_bytes(envelope.payload[4..8].try_into().expect("request_id bytes"));

        // Decrypt the remainder: seq_num(8 LE) | payload_len(4 BE) | payload.
        let encrypted = &envelope.payload[8..];
        let plaintext =
            decrypt_agent_data_at_offset(&self.key, &self.iv, self.ctr_offset, encrypted)
                .expect("decrypt callback payload");
        self.ctr_offset += ctr_blocks_for_len(encrypted.len());

        let _seq = u64::from_le_bytes(plaintext[0..8].try_into().expect("seq_num bytes"));
        let payload_len =
            u32::from_be_bytes(plaintext[8..12].try_into().expect("payload_len bytes")) as usize;
        let payload = plaintext[12..12 + payload_len].to_vec();

        (command_id, request_id, payload)
    }
}

// ---------------------------------------------------------------------------
// Task payload builders (little-endian, matching TaskParser expectations)
// ---------------------------------------------------------------------------

fn le_i32(v: i32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn le_u32_as_i32(v: u32) -> Vec<u8> {
    le_i32(v as i32)
}

fn le_bool(v: bool) -> Vec<u8> {
    le_i32(i32::from(v))
}

fn le_wstring(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (utf16.len() * 2) as i32;
    let mut out = byte_len.to_le_bytes().to_vec();
    for unit in &utf16 {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Build a CommandProc::Create payload that runs `/bin/sh -c <cmd>` with piped output.
fn build_shell_task_payload(cmd: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&le_u32_as_i32(u32::from(DemonProcessCommand::Create)));
    payload.extend_from_slice(&le_i32(0)); // process_state
    payload.extend_from_slice(&le_wstring("")); // process (empty → /bin/sh)
    payload.extend_from_slice(&le_wstring(cmd)); // process_args
    payload.extend_from_slice(&le_bool(true)); // piped
    payload.extend_from_slice(&le_bool(false)); // verbose
    payload
}

/// Build a CommandFs::Dir payload for a given path.
fn build_fs_dir_payload(path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&le_u32_as_i32(u32::from(DemonFilesystemCommand::Dir)));
    payload.extend_from_slice(&le_bool(false)); // file_explorer
    payload.extend_from_slice(&le_wstring(path)); // target
    payload.extend_from_slice(&le_bool(false)); // subdirs
    payload.extend_from_slice(&le_bool(false)); // files_only
    payload.extend_from_slice(&le_bool(false)); // dirs_only
    payload.extend_from_slice(&le_bool(false)); // list_only
    payload.extend_from_slice(&le_wstring("")); // starts
    payload.extend_from_slice(&le_wstring("")); // contains
    payload.extend_from_slice(&le_wstring("")); // ends
    payload
}

/// Build a CommandFs::Cat payload for a given path.
fn build_fs_cat_payload(path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&le_u32_as_i32(u32::from(DemonFilesystemCommand::Cat)));
    payload.extend_from_slice(&le_wstring(path));
    payload
}

/// Build a CommandProc::Grep payload with an empty needle (matches all).
fn build_proc_grep_payload(needle: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&le_u32_as_i32(u32::from(DemonProcessCommand::Grep)));
    payload.extend_from_slice(&le_wstring(needle));
    payload
}

/// Build a CommandNet::Sessions payload.
fn build_net_sessions_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&le_u32_as_i32(u32::from(DemonNetCommand::Sessions)));
    payload.extend_from_slice(&le_wstring("")); // target (empty → default)
    payload
}

/// Build a CommandExit payload with the given exit method.
fn build_exit_payload(exit_method: i32) -> Vec<u8> {
    le_i32(exit_method)
}

// ---------------------------------------------------------------------------
// HTTP helpers (same pattern as phantom's inline unit tests)
// ---------------------------------------------------------------------------

fn read_http_body(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        let read = stream.read(&mut buffer).expect("read from stream");
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);

        if header_end.is_none() {
            header_end = request.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
            if let Some(end) = header_end {
                let headers =
                    std::str::from_utf8(&request[..end]).expect("headers are valid UTF-8");
                content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length").then_some(value.trim())
                    })
                    .unwrap_or("0")
                    .parse::<usize>()
                    .expect("valid content-length");
            }
        }

        if let Some(end) = header_end {
            if request.len() >= end + content_length {
                break;
            }
        }
    }

    header_end.map_or_else(Vec::new, |end| request[end..].to_vec())
}

fn write_http_ok(stream: &mut std::net::TcpStream, body: &[u8]) {
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .expect("write HTTP header");
    stream.write_all(body).expect("write HTTP body");
}

// ---------------------------------------------------------------------------
// Response payload decoder helpers (LE encoding used in callback payloads)
// ---------------------------------------------------------------------------

/// Read a LE u32 at the given offset.
fn be_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().expect("le_u32"))
}

/// Read a LE-length-prefixed byte slice at the given offset, returning
/// (bytes, next_offset).
fn be_bytes(data: &[u8], offset: usize) -> (&[u8], usize) {
    let len = be_u32(data, offset) as usize;
    (&data[offset + 4..offset + 4 + len], offset + 4 + len)
}

/// Decode a LE-length-prefixed UTF-16LE string at the given offset.
fn be_utf16(data: &[u8], offset: usize) -> (String, usize) {
    let (raw, next) = be_bytes(data, offset);
    let utf16: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    (String::from_utf16_lossy(&utf16), next)
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

/// Create a PhantomAgent and mock server, perform init handshake, and return
/// the agent along with crypto state and channels for further interaction.
struct TestHarness {
    agent: PhantomAgent,
    crypto: MockCrypto,
    request_rx: mpsc::Receiver<Vec<u8>>,
    response_tx: mpsc::Sender<Vec<u8>>,
}

impl TestHarness {
    /// Set up a test harness: bind a mock server, create the agent, perform
    /// init handshake, and return ready-to-use state.
    ///
    /// `extra_connections` is the number of HTTP connections expected *after*
    /// init (the init itself is 1).
    async fn new(extra_connections: usize) -> (Self, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind mock server");
        let addr = listener.local_addr().expect("local addr");
        let (request_tx, request_rx) = mpsc::channel::<Vec<u8>>();
        let (response_tx, response_rx) = mpsc::channel::<Vec<u8>>();

        let config = PhantomConfig {
            callback_url: format!("http://{addr}/"),
            sleep_delay_ms: 0,
            sleep_jitter: 0,
            ..PhantomConfig::default()
        };
        let mut agent = PhantomAgent::new(config).expect("create agent");

        // Spawn server thread that handles init specially then uses channel
        // for subsequent connections.
        let init_tx = mpsc::Sender::clone(&request_tx);
        let server = thread::spawn(move || {
            // --- Connection 1: Init handshake ---
            let (mut stream, _) = listener.accept().expect("accept init");
            let init_body = read_http_body(&mut stream);
            let mut crypto = MockCrypto::from_init_body(&init_body);
            let ack = crypto.build_init_ack();
            write_http_ok(&mut stream, &ack);
            init_tx.send(init_body).expect("send init body");

            // Send crypto state to test via a side channel encoded in a request.
            // Actually, we need to send crypto state back. Let's encode it.
            // Simpler: serialize agent_id + key + iv + ctr_offset.
            let mut crypto_state = Vec::new();
            crypto_state.extend_from_slice(&crypto.agent_id.to_le_bytes());
            crypto_state.extend_from_slice(&crypto.key);
            crypto_state.extend_from_slice(&crypto.iv);
            crypto_state.extend_from_slice(&crypto.ctr_offset.to_le_bytes());
            init_tx.send(crypto_state).expect("send crypto state");

            // --- Remaining connections: channel-driven ---
            for _ in 0..extra_connections {
                let (mut stream, _) = listener.accept().expect("accept connection");
                let body = read_http_body(&mut stream);
                request_tx.send(body).expect("send request body");
                let response = response_rx.recv().expect("recv response body");
                write_http_ok(&mut stream, &response);
            }
        });

        agent.init_handshake().await.expect("init handshake");

        // Read init body (already verified by the agent succeeding).
        let _init_body = request_rx.recv().expect("recv init body");

        // Read crypto state from server thread.
        let crypto_state = request_rx.recv().expect("recv crypto state");
        let agent_id = u32::from_le_bytes(crypto_state[0..4].try_into().expect("agent_id bytes"));
        let key = crypto_state[4..4 + AGENT_KEY_LENGTH].to_vec();
        let iv =
            crypto_state[4 + AGENT_KEY_LENGTH..4 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH].to_vec();
        let ctr_offset_start = 4 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH;
        let ctr_offset = u64::from_le_bytes(
            crypto_state[ctr_offset_start..ctr_offset_start + 8]
                .try_into()
                .expect("ctr_offset bytes"),
        );

        let crypto = MockCrypto { agent_id, key, iv, ctr_offset };

        (Self { agent, crypto, request_rx, response_tx }, server)
    }

    /// Send empty responses for a checkin+get_job cycle (no tasks), verify packets.
    ///
    /// The new protocol requires two HTTP requests per checkin iteration:
    ///   1. `CommandCheckin` heartbeat → server returns empty
    ///   2. `CommandGetJob` fetch     → server returns empty (no queued tasks)
    async fn do_empty_checkin(&mut self) {
        // Queue empty responses for both checkin and get_job.
        self.response_tx.send(Vec::new()).expect("queue empty checkin response");
        self.response_tx.send(Vec::new()).expect("queue empty get_job response");

        let exit = self.agent.checkin().await.expect("checkin");
        assert!(!exit, "unexpected exit during empty checkin");

        // Verify checkin packet.
        let checkin_body = self.request_rx.recv().expect("recv checkin body");
        self.crypto.decrypt_checkin(&checkin_body);

        // Verify get_job packet.
        let get_job_body = self.request_rx.recv().expect("recv get_job body");
        self.crypto.decrypt_get_job(&get_job_body);
    }

    /// Queue a tasking response via `CommandGetJob`, have the agent check in, and
    /// return the collected callback bodies.
    ///
    /// The shared CTR offset advances in request/response order:
    ///   1. Agent sends checkin   → server decrypts (advances offset by 1 block)
    ///   2. Server replies empty  → no CTR advance
    ///   3. Agent sends get_job   → server decrypts (advances offset by 1 block)
    ///   4. Server sends tasks    → agent decrypts per-payload (advances offset)
    ///   5. Agent sends callbacks → server decrypts (advances offset per callback)
    async fn do_checkin_with_tasks(
        &mut self,
        packages: Vec<DemonPackage>,
        expected_callbacks: usize,
    ) -> Vec<(u32, u32, Vec<u8>)> {
        // Predict the offset at which task payloads will be encrypted.
        // checkin decrypt: 4 bytes encrypted = 1 block.
        // get_job decrypt: 4 bytes encrypted = 1 block.
        let inbound_blocks = ctr_blocks_for_len(4) + ctr_blocks_for_len(4); // 2
        let task_encrypt_start = self.crypto.ctr_offset + inbound_blocks;

        // Build the raw DemonMessage get_job response at the predicted offset.
        // `build_get_job_response` advances ctr_offset past the task payloads.
        let saved_offset = self.crypto.ctr_offset;
        self.crypto.ctr_offset = task_encrypt_start;
        let get_job_response = self.crypto.build_get_job_response(packages);
        let offset_after_tasks = self.crypto.ctr_offset;
        // Restore — the actual advance happens later when we decrypt packets.
        self.crypto.ctr_offset = saved_offset;

        // Queue responses: empty for checkin, task message for get_job, empty for callbacks.
        self.response_tx.send(Vec::new()).expect("queue empty checkin response");
        self.response_tx.send(get_job_response).expect("queue get_job response");
        for _ in 0..expected_callbacks {
            self.response_tx.send(Vec::new()).expect("queue callback ack");
        }

        let _exit = self.agent.checkin().await.expect("checkin with tasks");

        // Decrypt checkin (advances ctr_offset by 1).
        let checkin_body = self.request_rx.recv().expect("recv checkin body");
        self.crypto.decrypt_checkin(&checkin_body);

        // Decrypt get_job (advances ctr_offset by 1).
        let get_job_body = self.request_rx.recv().expect("recv get_job body");
        self.crypto.decrypt_get_job(&get_job_body);

        // Jump past the task payload blocks the agent decrypted from the response.
        self.crypto.ctr_offset = offset_after_tasks;

        // Read and decrypt all callback packets.
        let mut callbacks = Vec::new();
        for _ in 0..expected_callbacks {
            let body = self.request_rx.recv().expect("recv callback body");
            callbacks.push(self.crypto.decrypt_callback(&body));
        }

        callbacks
    }
}

// ---------------------------------------------------------------------------
// Scenario 1: Init handshake
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_1_init_handshake_registers_agent_with_metadata() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (req_tx, req_rx) = mpsc::channel::<Vec<u8>>();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let body = read_http_body(&mut stream);
        let mut crypto = MockCrypto::from_init_body(&body);
        let ack = crypto.build_init_ack();
        write_http_ok(&mut stream, &ack);
        req_tx.send(body).expect("send");
    });

    let config = PhantomConfig {
        callback_url: format!("http://{addr}/"),
        sleep_delay_ms: 0,
        ..PhantomConfig::default()
    };
    let mut agent = PhantomAgent::new(config).expect("agent");
    agent.init_handshake().await.expect("init");

    let init_body = req_rx.recv().expect("recv init");
    let envelope = DemonEnvelope::from_bytes(&init_body).expect("parse envelope");

    // Verify envelope structure.
    assert_ne!(envelope.header.agent_id, 0);
    assert!(envelope.header.agent_id & 1 == 1, "agent_id should be odd");

    // Extract raw crypto from payload.
    let key = &envelope.payload[8..8 + AGENT_KEY_LENGTH];
    let iv = &envelope.payload[8 + AGENT_KEY_LENGTH..8 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH];
    assert_eq!(key.len(), AGENT_KEY_LENGTH);
    assert_eq!(iv.len(), AGENT_IV_LENGTH);

    // Decrypt metadata.
    let encrypted = &envelope.payload[8 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH..];
    let metadata =
        red_cell_common::crypto::decrypt_agent_data(key, iv, encrypted).expect("decrypt metadata");

    // First 4 bytes are agent_id (BE).
    let meta_agent_id = u32::from_be_bytes(metadata[0..4].try_into().expect("meta agent_id"));
    assert_eq!(meta_agent_id, envelope.header.agent_id);

    // Next: hostname (BE length-prefixed UTF-8).
    let hostname_len = u32::from_be_bytes(metadata[4..8].try_into().expect("hostname len"));
    assert!(hostname_len > 0, "hostname should not be empty");
    let hostname =
        std::str::from_utf8(&metadata[8..8 + hostname_len as usize]).expect("hostname utf8");
    assert!(!hostname.is_empty());

    // Verify we got past hostname — the metadata contains many more fields.
    // Just verify the total size is reasonable (all fields present).
    assert!(metadata.len() > 80, "metadata should contain all fields");

    server.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Scenario 2: Checkin loop (3 checkins without error)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_2_checkin_loop_three_successful_checkins() {
    // 3 empty checkins × 2 requests each (checkin + get_job) = 6 connections.
    let (mut harness, server) = TestHarness::new(6).await;

    for i in 0..3 {
        harness.do_empty_checkin().await;
        eprintln!("checkin {}/3 ok", i + 1);
    }

    server.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Scenario 3: Shell command
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_3_shell_command_echo() {
    // checkin (2 req: checkin + get_job) + 2 callbacks = 4 connections.
    let (mut harness, server) = TestHarness::new(4).await;

    let task = DemonPackage::new(
        DemonCommand::CommandProc,
        100,
        build_shell_task_payload("echo phantom-ok"),
    );
    let callbacks = harness.do_checkin_with_tasks(vec![task], 2).await;

    // First callback: Structured proc_create.
    let (cmd_id, req_id, _payload) = &callbacks[0];
    assert_eq!(*cmd_id, u32::from(DemonCommand::CommandProc));
    assert_eq!(*req_id, 100);

    // Second callback: Output containing "phantom-ok".
    let (cmd_id, req_id, payload) = &callbacks[1];
    assert_eq!(*cmd_id, u32::from(DemonCommand::CommandOutput));
    assert_eq!(*req_id, 100);
    // Output payload is BE-length-prefixed UTF-8 bytes.
    let (output_bytes, _) = be_bytes(payload, 0);
    let output = std::str::from_utf8(output_bytes).expect("output utf8");
    assert!(output.contains("phantom-ok"), "expected 'phantom-ok' in output, got: {output:?}");

    server.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Scenario 4: Filesystem (Dir + Cat)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_4_filesystem_dir_and_cat() {
    // checkin (2 req: checkin + get_job) + 2 callbacks = 4 connections.
    let (mut harness, server) = TestHarness::new(4).await;

    let dir_task = DemonPackage::new(DemonCommand::CommandFs, 200, build_fs_dir_payload("/tmp"));
    let cat_task =
        DemonPackage::new(DemonCommand::CommandFs, 201, build_fs_cat_payload("/etc/hostname"));
    let callbacks = harness.do_checkin_with_tasks(vec![dir_task, cat_task], 2).await;

    // First callback: Dir listing for /tmp.
    let (cmd_id, req_id, payload) = &callbacks[0];
    assert_eq!(*cmd_id, u32::from(DemonCommand::CommandFs));
    assert_eq!(*req_id, 200);
    // Payload starts with subcommand (BE u32 = Dir = 1).
    let subcommand = be_u32(payload, 0);
    assert_eq!(subcommand, u32::from(DemonFilesystemCommand::Dir));

    // Second callback: Cat of /etc/hostname.
    let (cmd_id, req_id, payload) = &callbacks[1];
    assert_eq!(*cmd_id, u32::from(DemonCommand::CommandFs));
    assert_eq!(*req_id, 201);
    let subcommand = be_u32(payload, 0);
    assert_eq!(subcommand, u32::from(DemonFilesystemCommand::Cat));
    // Payload: subcommand(4) + utf16_path + bool(success=true) + bytes(content).
    // Decode the path (skip subcommand).
    let (_path, next) = be_utf16(payload, 4);
    // Next is a bool (success).
    let success = be_u32(payload, next);
    assert_eq!(success, 1, "cat should succeed");
    // Next is file contents.
    let (content_bytes, _) = be_bytes(payload, next + 4);
    let content = std::str::from_utf8(content_bytes).expect("content utf8");
    // Compare with actual hostname.
    let expected =
        std::fs::read_to_string("/etc/hostname").expect("read /etc/hostname").trim().to_string();
    assert!(
        content.contains(&expected),
        "expected hostname '{expected}' in cat output, got: {content:?}"
    );

    server.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Scenario 5: Process list (Grep)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_5_process_list_contains_own_pid() {
    // checkin (2 req: checkin + get_job) + 1 callback = 3 connections.
    let (mut harness, server) = TestHarness::new(3).await;

    // Use empty needle to match all processes.
    let task = DemonPackage::new(DemonCommand::CommandProc, 300, build_proc_grep_payload(""));
    let callbacks = harness.do_checkin_with_tasks(vec![task], 1).await;

    let (cmd_id, req_id, payload) = &callbacks[0];
    assert_eq!(*cmd_id, u32::from(DemonCommand::CommandProc));
    assert_eq!(*req_id, 300);

    // Payload: subcommand(4) + repeated [utf16(name), u32(pid), u32(ppid), utf16(user), u32(arch)]
    let subcommand = be_u32(payload, 0);
    assert_eq!(subcommand, u32::from(DemonProcessCommand::Grep));

    // Search for our own PID in the process list.
    let our_pid = std::process::id();
    let mut offset = 4;
    let mut found_own_pid = false;
    while offset < payload.len() {
        // name (utf16)
        let (_name, next) = be_utf16(payload, offset);
        // pid (u32)
        let pid = be_u32(payload, next);
        // ppid (u32)
        let _ppid = be_u32(payload, next + 4);
        // user (utf16)
        let (_user, next2) = be_utf16(payload, next + 8);
        // arch (u32)
        let _arch = be_u32(payload, next2);
        offset = next2 + 4;

        if pid == our_pid {
            found_own_pid = true;
            break;
        }
    }
    assert!(found_own_pid, "process list should contain PID {our_pid}");

    server.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Scenario 6: Network Sessions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_6_network_sessions() {
    // checkin (2 req: checkin + get_job) + 1 callback = 3 connections.
    let (mut harness, server) = TestHarness::new(3).await;

    let task = DemonPackage::new(DemonCommand::CommandNet, 400, build_net_sessions_payload());
    let callbacks = harness.do_checkin_with_tasks(vec![task], 1).await;

    let (cmd_id, req_id, payload) = &callbacks[0];
    assert_eq!(*cmd_id, u32::from(DemonCommand::CommandNet));
    assert_eq!(*req_id, 400);

    // Payload: subcommand(4) + utf16(target) + optional session entries.
    let subcommand = be_u32(payload, 0);
    assert_eq!(subcommand, u32::from(DemonNetCommand::Sessions));

    // Verify we can decode the target string (valid structure).
    let (target, _next) = be_utf16(payload, 4);
    // Target should be the hostname or "localhost" (from default_net_target).
    assert!(!target.is_empty(), "session target should not be empty");

    // The session list may be empty — that's valid.
    // Just verify the payload is well-formed (no crash during decode).

    server.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Scenario 7: Exit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_7_exit_clean_shutdown() {
    // checkin (2 req: checkin + get_job) + 1 exit callback = 3 connections.
    let (mut harness, server) = TestHarness::new(3).await;

    let task = DemonPackage::new(DemonCommand::CommandExit, 500, build_exit_payload(1));
    let callbacks = harness.do_checkin_with_tasks(vec![task], 1).await;

    let (cmd_id, req_id, payload) = &callbacks[0];
    assert_eq!(*cmd_id, u32::from(DemonCommand::CommandExit));
    assert_eq!(*req_id, 500);
    // Exit payload is the exit method (LE u32).
    let exit_method = u32::from_le_bytes(payload[0..4].try_into().expect("exit method"));
    assert_eq!(exit_method, 1);

    server.join().expect("server thread");
}
