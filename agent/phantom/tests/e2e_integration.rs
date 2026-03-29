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
    /// CTR block offset for data we *send* to the agent (agent's recv side).
    send_ctr_offset: u64,
    /// CTR block offset for data we *receive* from the agent (agent's send side).
    recv_ctr_offset: u64,
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
        Self { agent_id, key, iv, send_ctr_offset: 0, recv_ctr_offset: 0 }
    }

    /// Build the encrypted init acknowledgement.
    fn build_init_ack(&mut self) -> Vec<u8> {
        let ack = encrypt_agent_data(&self.key, &self.iv, &self.agent_id.to_le_bytes())
            .expect("encrypt init ack");
        self.send_ctr_offset = ctr_blocks_for_len(ack.len());
        ack
    }

    /// Encrypt a tasking response (DemonMessage wrapped in DemonEnvelope).
    fn encrypt_tasking(&mut self, packages: Vec<DemonPackage>) -> Vec<u8> {
        if packages.is_empty() {
            return Vec::new();
        }
        let message = DemonMessage::new(packages);
        let plaintext = message.to_bytes().expect("encode tasking message");
        let encrypted =
            encrypt_agent_data_at_offset(&self.key, &self.iv, self.send_ctr_offset, &plaintext)
                .expect("encrypt tasking");
        let envelope =
            DemonEnvelope::new(self.agent_id, encrypted.clone()).expect("build tasking envelope");
        let bytes = envelope.to_bytes();
        self.send_ctr_offset += ctr_blocks_for_len(encrypted.len());
        bytes
    }

    /// Decrypt and advance CTR, returning raw plaintext from the envelope.
    fn decrypt_envelope(&mut self, body: &[u8]) -> Vec<u8> {
        let envelope = DemonEnvelope::from_bytes(body).expect("parse envelope");
        assert_eq!(envelope.header.agent_id, self.agent_id);
        let plaintext = decrypt_agent_data_at_offset(
            &self.key,
            &self.iv,
            self.recv_ctr_offset,
            &envelope.payload,
        )
        .expect("decrypt envelope");
        self.recv_ctr_offset += ctr_blocks_for_len(envelope.payload.len());
        plaintext
    }

    /// Decrypt a COMMAND_CHECKIN packet (DemonMessage, LE encoding).
    fn decrypt_checkin(&mut self, body: &[u8]) -> DemonMessage {
        let plaintext = self.decrypt_envelope(body);
        DemonMessage::from_bytes(&plaintext).expect("parse checkin DemonMessage")
    }

    /// Decrypt a callback packet (BE header: command_id, request_id, payload_len, payload).
    fn decrypt_callback(&mut self, body: &[u8]) -> (u32, u32, Vec<u8>) {
        let plaintext = self.decrypt_envelope(body);

        let command_id = u32::from_be_bytes(plaintext[0..4].try_into().expect("command_id bytes"));
        let request_id = u32::from_be_bytes(plaintext[4..8].try_into().expect("request_id bytes"));
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
// Response payload decoder helpers (BE encoding used in callback payloads)
// ---------------------------------------------------------------------------

/// Read a BE u32 at the given offset.
fn be_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().expect("be_u32"))
}

/// Read a BE-length-prefixed byte slice at the given offset, returning
/// (bytes, next_offset).
fn be_bytes(data: &[u8], offset: usize) -> (&[u8], usize) {
    let len = be_u32(data, offset) as usize;
    (&data[offset + 4..offset + 4 + len], offset + 4 + len)
}

/// Decode a BE-length-prefixed UTF-16LE string at the given offset.
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
            // Simpler: serialize agent_id + key + iv + send_ctr_offset.
            let mut crypto_state = Vec::new();
            crypto_state.extend_from_slice(&crypto.agent_id.to_le_bytes());
            crypto_state.extend_from_slice(&crypto.key);
            crypto_state.extend_from_slice(&crypto.iv);
            crypto_state.extend_from_slice(&crypto.send_ctr_offset.to_le_bytes());
            crypto_state.extend_from_slice(&crypto.recv_ctr_offset.to_le_bytes());
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
        let send_offset_start = 4 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH;
        let send_ctr_offset = u64::from_le_bytes(
            crypto_state[send_offset_start..send_offset_start + 8]
                .try_into()
                .expect("send_ctr bytes"),
        );
        let recv_ctr_offset = u64::from_le_bytes(
            crypto_state[send_offset_start + 8..send_offset_start + 16]
                .try_into()
                .expect("recv_ctr bytes"),
        );

        let crypto = MockCrypto { agent_id, key, iv, send_ctr_offset, recv_ctr_offset };

        (Self { agent, crypto, request_rx, response_tx }, server)
    }

    /// Send an empty tasking response (no tasks), have the agent check in, and
    /// verify the checkin packet is valid.
    async fn do_empty_checkin(&mut self) {
        // Queue empty response (no tasks).
        self.response_tx.send(Vec::new()).expect("queue empty response");
        let exit = self.agent.checkin().await.expect("checkin");
        assert!(!exit, "unexpected exit during empty checkin");

        // Read and verify the checkin packet (DemonMessage, LE).
        let checkin_body = self.request_rx.recv().expect("recv checkin body");
        let message = self.crypto.decrypt_checkin(&checkin_body);
        assert_eq!(message.packages.len(), 1);
        assert_eq!(message.packages[0].command().expect("command"), DemonCommand::CommandCheckin);
    }

    /// Queue a tasking response with the given packages, have the agent check
    /// in, and return the collected callback bodies.
    async fn do_checkin_with_tasks(
        &mut self,
        packages: Vec<DemonPackage>,
        expected_callbacks: usize,
    ) -> Vec<(u32, u32, Vec<u8>)> {
        // Queue the tasking response.
        let tasking = self.crypto.encrypt_tasking(packages);
        self.response_tx.send(tasking).expect("queue tasking response");

        // Queue empty responses for each expected callback.
        for _ in 0..expected_callbacks {
            self.response_tx.send(Vec::new()).expect("queue callback ack");
        }

        let exit = self.agent.checkin().await.expect("checkin with tasks");

        // Read the checkin packet first (DemonMessage, LE).
        let checkin_body = self.request_rx.recv().expect("recv checkin body");
        let message = self.crypto.decrypt_checkin(&checkin_body);
        assert_eq!(message.packages.len(), 1);
        assert_eq!(message.packages[0].command().expect("command"), DemonCommand::CommandCheckin);

        // Read all callback packets.
        let mut callbacks = Vec::new();
        for _ in 0..expected_callbacks {
            let body = self.request_rx.recv().expect("recv callback body");
            callbacks.push(self.crypto.decrypt_callback(&body));
        }

        if exit {
            // Don't assert !exit here — caller decides.
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
    // 3 empty checkins = 3 connections.
    let (mut harness, server) = TestHarness::new(3).await;

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
    // 1 checkin + 2 callbacks (Structured proc_create + Output).
    let (mut harness, server) = TestHarness::new(3).await;

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
    // 1 checkin + 2 callbacks (one per task).
    let (mut harness, server) = TestHarness::new(3).await;

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
    // 1 checkin + 1 callback.
    let (mut harness, server) = TestHarness::new(2).await;

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
    // 1 checkin + 1 callback.
    let (mut harness, server) = TestHarness::new(2).await;

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
    // 1 checkin + 1 callback (exit callback).
    let (mut harness, server) = TestHarness::new(2).await;

    let task = DemonPackage::new(DemonCommand::CommandExit, 500, build_exit_payload(1));

    // Queue the tasking response.
    let tasking = harness.crypto.encrypt_tasking(vec![task]);
    harness.response_tx.send(tasking).expect("queue tasking");
    // Queue empty response for exit callback.
    harness.response_tx.send(Vec::new()).expect("queue callback ack");

    let exit = harness.agent.checkin().await.expect("checkin with exit");
    assert!(exit, "checkin should signal exit");

    // Read the checkin packet (DemonMessage, LE).
    let checkin_body = harness.request_rx.recv().expect("recv checkin");
    let message = harness.crypto.decrypt_checkin(&checkin_body);
    assert_eq!(message.packages.len(), 1);
    assert_eq!(message.packages[0].command().expect("command"), DemonCommand::CommandCheckin);

    // Read the exit callback.
    let exit_body = harness.request_rx.recv().expect("recv exit callback");
    let (cmd_id, req_id, payload) = harness.crypto.decrypt_callback(&exit_body);
    assert_eq!(cmd_id, u32::from(DemonCommand::CommandExit));
    assert_eq!(req_id, 500);
    // Exit payload is the exit method (BE u32).
    let exit_method = u32::from_be_bytes(payload[0..4].try_into().expect("exit method"));
    assert_eq!(exit_method, 1);

    server.join().expect("server thread");
}
