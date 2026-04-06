//! End-to-end integration tests for the Specter agent.
//!
//! These tests spin up a mock teamserver (raw HTTP + Demon protocol) and drive
//! the Specter agent through a complete lifecycle: init handshake, checkins,
//! encrypted tasking via `get_job`, shell command, filesystem ops, process
//! listing, and exit.
//!
//! # Monotonic CTR
//!
//! Unlike Phantom (which tracks separate send/recv CTR offsets), Specter uses a
//! single **monotonic** CTR offset shared by both sides.  Every encrypted
//! operation — init ACK, callback payload, job response payload — advances the
//! same counter on both the agent and the mock server.  The test harness tracks
//! this state via [`MockSpecterCrypto`].
//!
//! # Agent entry point
//!
//! Most scenarios drive the agent through `SpecterAgent::run()`, which calls
//! `init_handshake()` internally, then loops: `checkin() → get_job() →
//! dispatch() → callbacks`.  With `sleep_delay_ms: 0` no real sleep occurs.
//!
//! Run with: `cargo nextest run --package specter` (or `cargo test --package specter`)

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data,
    decrypt_agent_data_at_offset, encrypt_agent_data, encrypt_agent_data_at_offset,
};
use red_cell_common::demon::{
    DemonCommand, DemonEnvelope, DemonFilesystemCommand, DemonMessage, DemonPackage,
    DemonProcessCommand,
};

use specter::{SpecterAgent, SpecterConfig};

// ---------------------------------------------------------------------------
// Mock teamserver — server-side crypto state (monotonic CTR)
// ---------------------------------------------------------------------------

/// Monotonic-CTR crypto state mirroring the teamserver side.
///
/// Specter uses a single shared counter for all encrypt/decrypt operations.
/// Both the agent and the mock server advance `ctr_offset` by the same number
/// of CTR blocks after every operation.
struct MockSpecterCrypto {
    agent_id: u32,
    key: Vec<u8>,
    iv: Vec<u8>,
    /// Shared monotonic CTR block offset.
    ctr_offset: u64,
}

impl MockSpecterCrypto {
    /// Extract crypto material from a `DEMON_INIT` packet body.
    ///
    /// Payload layout (after the DemonEnvelope header):
    /// `[command_id:4][request_id:4][raw_key:32][raw_iv:16][encrypted_metadata…]`
    fn from_init_body(body: &[u8]) -> Self {
        let envelope = DemonEnvelope::from_bytes(body).expect("parse init envelope");
        let agent_id = envelope.header.agent_id;
        let key = envelope.payload[8..8 + AGENT_KEY_LENGTH].to_vec();
        let iv =
            envelope.payload[8 + AGENT_KEY_LENGTH..8 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH].to_vec();
        Self { agent_id, key, iv, ctr_offset: 0 }
    }

    /// Encrypt the agent_id acknowledgement and advance the shared CTR.
    ///
    /// The teamserver encrypts `agent_id` (4 bytes, little-endian) at CTR
    /// offset 0.  One AES block is consumed: `ctr_offset` becomes 1 after this
    /// call.
    fn build_init_ack(&mut self) -> Vec<u8> {
        let ack = encrypt_agent_data(&self.key, &self.iv, &self.agent_id.to_le_bytes())
            .expect("encrypt init ack");
        self.ctr_offset += ctr_blocks_for_len(ack.len());
        ack
    }

    /// Decrypt an incoming callback packet and advance the shared CTR.
    ///
    /// The Demon protocol uses a two-layer encoding:
    ///
    /// * **Outer envelope** (not encrypted): `[command_id:4,BE][request_id:4,BE]`
    ///   These fields are big-endian per the Demon wire protocol, matching what the
    ///   teamserver's `parse_callback_packages` reads with `read_u32_be`.
    ///
    /// * **Encrypted inner payload**: `[seq_num:8,LE][payload_len:4,BE][payload_bytes…]`
    ///   The 8-byte sequence number prefix is little-endian and is skipped by the
    ///   teamserver after decryption.  The length prefix is big-endian (matching
    ///   `read_length_prefixed_bytes_be`).  The `payload_bytes` themselves are
    ///   **little-endian** — individual fields are encoded with `write_u32_le` /
    ///   `write_utf16le` so they are compatible with the teamserver's
    ///   `CallbackParser::read_u32` / `read_utf16` methods.
    ///
    /// Returns `(command_id, request_id, decrypted_payload_bytes)`.  The caller
    /// must decode `decrypted_payload_bytes` with little-endian helpers.
    fn decrypt_callback(&mut self, body: &[u8]) -> (u32, u32, Vec<u8>) {
        let envelope = DemonEnvelope::from_bytes(body).expect("parse callback envelope");
        assert_eq!(envelope.header.agent_id, self.agent_id, "agent_id mismatch in callback");

        let command_id = u32::from_be_bytes(envelope.payload[0..4].try_into().expect("command_id"));
        let request_id = u32::from_be_bytes(envelope.payload[4..8].try_into().expect("request_id"));
        let encrypted = &envelope.payload[8..];

        let decrypted =
            decrypt_agent_data_at_offset(&self.key, &self.iv, self.ctr_offset, encrypted)
                .expect("decrypt callback payload");

        // Encrypted region is `seq_num(8) + payload_len(4) + payload` — same length as ciphertext.
        self.ctr_offset += ctr_blocks_for_len(encrypted.len());

        let _seq = u64::from_le_bytes(decrypted[0..8].try_into().expect("seq_num"));
        let payload_len =
            u32::from_be_bytes(decrypted[8..12].try_into().expect("payload_len")) as usize;
        let payload = decrypted[12..12 + payload_len].to_vec();

        (command_id, request_id, payload)
    }

    /// Build a `get_job` response with encrypted task package payloads.
    ///
    /// Each non-empty payload is encrypted at the current `ctr_offset`, which
    /// is then advanced by the consumed blocks.  The returned bytes are a raw
    /// `DemonMessage` (little-endian package stream) ready to be sent as the
    /// HTTP response body.
    fn build_job_response(&mut self, tasks: Vec<(u32, u32, Vec<u8>)>) -> Vec<u8> {
        if tasks.is_empty() {
            return Vec::new();
        }
        let packages: Vec<DemonPackage> = tasks
            .into_iter()
            .map(|(command_id, request_id, payload)| {
                if payload.is_empty() {
                    DemonPackage { command_id, request_id, payload: Vec::new() }
                } else {
                    let encrypted = encrypt_agent_data_at_offset(
                        &self.key,
                        &self.iv,
                        self.ctr_offset,
                        &payload,
                    )
                    .expect("encrypt task payload");
                    self.ctr_offset += ctr_blocks_for_len(encrypted.len());
                    DemonPackage { command_id, request_id, payload: encrypted }
                }
            })
            .collect();
        DemonMessage::new(packages).to_bytes().expect("encode DemonMessage")
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
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
// Task payload builders — little-endian, matching Specter's TaskParser
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

/// Build a `CommandProc::Create` payload that runs `/bin/sh -c <cmd>`.
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

/// Build a `CommandFs::Dir` payload for the given path.
fn build_fs_dir_payload(path: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&le_u32_as_i32(u32::from(DemonFilesystemCommand::Dir)));
    payload.extend_from_slice(&le_bool(false)); // file_explorer
    payload.extend_from_slice(&le_wstring(path));
    payload.extend_from_slice(&le_bool(false)); // subdirs
    payload.extend_from_slice(&le_bool(false)); // files_only
    payload.extend_from_slice(&le_bool(false)); // dirs_only
    payload.extend_from_slice(&le_bool(false)); // list_only
    payload.extend_from_slice(&le_wstring("")); // starts
    payload.extend_from_slice(&le_wstring("")); // contains
    payload.extend_from_slice(&le_wstring("")); // ends
    payload
}

/// Build a `CommandFs::GetPwd` payload.
fn build_fs_getpwd_payload() -> Vec<u8> {
    le_u32_as_i32(u32::from(DemonFilesystemCommand::GetPwd))
}

/// Build a `CommandProc::Grep` payload with the given needle.
fn build_proc_grep_payload(needle: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&le_u32_as_i32(u32::from(DemonProcessCommand::Grep)));
    payload.extend_from_slice(&le_wstring(needle));
    payload
}

/// Build a `CommandProcList` payload (process_ui flag = 0).
fn build_proc_list_payload() -> Vec<u8> {
    le_u32_as_i32(0) // process_ui flag
}

/// Build a `CommandSleep` payload.
fn build_sleep_payload(delay_ms: u32, jitter: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&delay_ms.to_le_bytes());
    payload.extend_from_slice(&jitter.to_le_bytes());
    payload
}

// ---------------------------------------------------------------------------
// Response payload decoder helpers — little-endian (agent → server payload body)
//
// The outer Demon callback envelope fields (command_id, request_id, payload_len)
// are big-endian per the Demon wire protocol and are handled by `decrypt_callback`
// above.  The payload *content* returned by that function is little-endian, matching
// the Rust teamserver's `CallbackParser::read_u32`/`read_utf16`/etc. methods.
// ---------------------------------------------------------------------------

fn le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().expect("le_u32"))
}

fn le_bytes(data: &[u8], offset: usize) -> (&[u8], usize) {
    let len = le_u32(data, offset) as usize;
    (&data[offset + 4..offset + 4 + len], offset + 4 + len)
}

fn le_utf16(data: &[u8], offset: usize) -> (String, usize) {
    let (raw, next) = le_bytes(data, offset);
    let utf16: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    (String::from_utf16_lossy(&utf16), next)
}

// ---------------------------------------------------------------------------
// Verify the init packet structure (standalone helper)
// ---------------------------------------------------------------------------

fn verify_init_body(body: &[u8]) -> MockSpecterCrypto {
    let envelope = DemonEnvelope::from_bytes(body).expect("parse init envelope");
    let agent_id = envelope.header.agent_id;

    assert_ne!(agent_id, 0, "agent_id must not be zero");
    assert_eq!(agent_id & 1, 1, "agent_id should be odd (LSB forced)");

    let key = &envelope.payload[8..8 + AGENT_KEY_LENGTH];
    let iv = &envelope.payload[8 + AGENT_KEY_LENGTH..8 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH];

    // Decrypt metadata to verify the packet is well-formed.
    let encrypted = &envelope.payload[8 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH..];
    let metadata = decrypt_agent_data(key, iv, encrypted).expect("decrypt init metadata");

    // First 4 bytes = agent_id (BE).
    let meta_agent_id = u32::from_be_bytes(metadata[0..4].try_into().expect("meta agent_id"));
    assert_eq!(meta_agent_id, agent_id, "metadata agent_id must match envelope agent_id");

    // Specter appends INIT_EXT_MONOTONIC_CTR flag (u32 = 1) at the end.
    let last4 = &metadata[metadata.len() - 4..];
    let ext_flags = u32::from_be_bytes(last4.try_into().expect("ext_flags"));
    assert_eq!(ext_flags & 1, 1, "Specter must set INIT_EXT_MONOTONIC_CTR flag");

    MockSpecterCrypto { agent_id, key: key.to_vec(), iv: iv.to_vec(), ctr_offset: 0 }
}

// ---------------------------------------------------------------------------
// Mock server runner for `run()`-based tests
//
// Pre-programs a fixed connection sequence and returns collected callbacks.
// ---------------------------------------------------------------------------

/// A collected callback from a dispatch result.
#[derive(Debug)]
struct CollectedCallback {
    command_id: u32,
    request_id: u32,
    payload: Vec<u8>,
}

/// Runs a mock server thread that handles the full `run()` lifecycle.
///
/// Connection sequence:
/// 1. INIT
/// 2. CHECKIN (empty response)
/// 3. GET_JOB → send `first_cycle_tasks`
/// 4. For each expected callback: receive and collect
/// 5. CHECKIN (empty response)
/// 6. GET_JOB → send exit task (CommandExit with empty payload)
///
/// Returns a thread handle and a receiver for collected callbacks.
fn spawn_mock_server(
    listener: TcpListener,
    first_cycle_tasks: Vec<(u32, u32, Vec<u8>)>,
    expected_callbacks: usize,
) -> (thread::JoinHandle<Vec<CollectedCallback>>, std::net::SocketAddr) {
    let addr = listener.local_addr().expect("local addr");

    let handle = thread::spawn(move || {
        let mut callbacks = Vec::new();

        // ── Connection 0: INIT ──────────────────────────────────────────────
        let (mut stream, _) = listener.accept().expect("accept init");
        let body = read_http_body(&mut stream);
        let mut crypto = verify_init_body(&body);
        let ack = crypto.build_init_ack();
        write_http_ok(&mut stream, &ack);

        // ── Connection 1: CHECKIN (cycle 1) ────────────────────────────────
        let (mut stream, _) = listener.accept().expect("accept checkin-1");
        let body = read_http_body(&mut stream);
        let (cmd, _, _) = crypto.decrypt_callback(&body);
        assert_eq!(cmd, u32::from(DemonCommand::CommandCheckin), "expected CommandCheckin");
        write_http_ok(&mut stream, &[]); // empty → no inline tasking

        // ── Connection 2: GET_JOB (cycle 1) → inject tasks ─────────────────
        let (mut stream, _) = listener.accept().expect("accept getjob-1");
        let body = read_http_body(&mut stream);
        let (cmd, _, _) = crypto.decrypt_callback(&body);
        assert_eq!(cmd, u32::from(DemonCommand::CommandGetJob), "expected CommandGetJob");
        let response = crypto.build_job_response(first_cycle_tasks);
        write_http_ok(&mut stream, &response);

        // ── Connections 3…(3+N-1): dispatch callbacks ──────────────────────
        for _ in 0..expected_callbacks {
            let (mut stream, _) = listener.accept().expect("accept dispatch callback");
            let body = read_http_body(&mut stream);
            let (cmd, req, payload) = crypto.decrypt_callback(&body);
            callbacks.push(CollectedCallback { command_id: cmd, request_id: req, payload });
            write_http_ok(&mut stream, &[]); // agent ignores this response
        }

        // ── Connection (3+N): CHECKIN (cycle 2) ────────────────────────────
        let (mut stream, _) = listener.accept().expect("accept checkin-2");
        let body = read_http_body(&mut stream);
        let (cmd, _, _) = crypto.decrypt_callback(&body);
        assert_eq!(
            cmd,
            u32::from(DemonCommand::CommandCheckin),
            "expected CommandCheckin (cycle 2)"
        );
        write_http_ok(&mut stream, &[]);

        // ── Connection (4+N): GET_JOB (cycle 2) → inject exit ──────────────
        let (mut stream, _) = listener.accept().expect("accept getjob-2");
        let body = read_http_body(&mut stream);
        let (cmd, _, _) = crypto.decrypt_callback(&body);
        assert_eq!(cmd, u32::from(DemonCommand::CommandGetJob), "expected CommandGetJob (cycle 2)");
        // Send exit task (empty payload — dispatch ignores payload for CommandExit).
        let exit_tasks = vec![(u32::from(DemonCommand::CommandExit), 0xFFFF_u32, Vec::new())];
        let exit_response = crypto.build_job_response(exit_tasks);
        write_http_ok(&mut stream, &exit_response);

        callbacks
    });

    (handle, addr)
}

// ---------------------------------------------------------------------------
// Scenario 1: Init handshake — packet structure and CTR synchronisation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_1_init_handshake_ctr_starts_at_one() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let body = read_http_body(&mut stream);
        let mut crypto = verify_init_body(&body);
        let ack = crypto.build_init_ack();
        write_http_ok(&mut stream, &ack);
        // After building the ack, ctr_offset should be 1.
        crypto.ctr_offset
    });

    let config = SpecterConfig {
        callback_url: format!("http://{addr}/"),
        sleep_delay_ms: 0,
        ..SpecterConfig::default()
    };
    let mut agent = SpecterAgent::new(config).expect("create agent");
    agent.init_handshake().await.expect("init handshake");

    // Monotonic CTR: both sides must agree at offset 1 after init ACK.
    let agent_ctr = agent.ctr_offset();
    assert_eq!(agent_ctr, 1, "agent CTR must be 1 after init ACK");

    let server_ctr = server.join().expect("server thread");
    assert_eq!(server_ctr, 1, "server CTR must be 1 after init ACK");
    assert_eq!(agent_ctr, server_ctr, "agent and server CTR must agree after init");
}

// ---------------------------------------------------------------------------
// Scenario 2: Checkin + get_job loop — manual API, 3 cycles, no tasks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_2_empty_checkin_and_get_job_loop_three_cycles() {
    // 1 init + 3 × (1 checkin + 1 get_job) = 7 connections.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");

    let (ctr_tx, ctr_rx) = mpsc::channel::<u64>();

    let server = thread::spawn(move || {
        // Init
        let (mut stream, _) = listener.accept().expect("accept init");
        let body = read_http_body(&mut stream);
        let mut crypto = MockSpecterCrypto::from_init_body(&body);
        let ack = crypto.build_init_ack();
        write_http_ok(&mut stream, &ack);

        for cycle in 0..3_u32 {
            // Checkin
            let (mut stream, _) = listener.accept().expect(&format!("accept checkin {cycle}"));
            let body = read_http_body(&mut stream);
            let (cmd, req, _) = crypto.decrypt_callback(&body);
            assert_eq!(cmd, u32::from(DemonCommand::CommandCheckin));
            assert_eq!(req, 0);
            write_http_ok(&mut stream, &[]);

            // GetJob — no tasks
            let (mut stream, _) = listener.accept().expect(&format!("accept getjob {cycle}"));
            let body = read_http_body(&mut stream);
            let (cmd, req, _) = crypto.decrypt_callback(&body);
            assert_eq!(cmd, u32::from(DemonCommand::CommandGetJob));
            assert_eq!(req, 0);
            write_http_ok(&mut stream, &[]);
        }

        ctr_tx.send(crypto.ctr_offset).expect("send server ctr");
    });

    let config = SpecterConfig {
        callback_url: format!("http://{addr}/"),
        sleep_delay_ms: 0,
        ..SpecterConfig::default()
    };
    let mut agent = SpecterAgent::new(config).expect("create agent");
    agent.init_handshake().await.expect("init");

    for _ in 0..3 {
        let checkin_result = agent.checkin().await.expect("checkin");
        assert!(checkin_result.is_empty(), "checkin with no tasks should return empty bytes");

        let job = agent.get_job().await.expect("get_job");
        assert!(job.packages.is_empty(), "get_job with no tasks should return empty message");
    }

    // CTR must advance by 2 (1 checkin + 1 get_job) per cycle after the init CTR of 1.
    // Expected final CTR: 1 (init) + 3×2 (cycles) = 7.
    assert_eq!(agent.ctr_offset(), 7, "agent CTR must be 7 after 3 cycles");

    let server_ctr = ctr_rx.recv().expect("recv server ctr");
    assert_eq!(server_ctr, 7, "server CTR must be 7 after 3 cycles");
    assert_eq!(agent.ctr_offset(), server_ctr, "agent and server CTR must agree after 3 cycles");

    server.join().expect("server thread");
}

// ---------------------------------------------------------------------------
// Scenario 3: Shell command — full lifecycle via run()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_3_shell_command_echo() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let shell_task = vec![(
        u32::from(DemonCommand::CommandProc),
        100_u32,
        build_shell_task_payload("echo specter-ok"),
    )];
    // Shell command → MultiRespond([proc_create, output]) = 2 callbacks.
    let (server, addr) = spawn_mock_server(listener, shell_task, 2);

    let config = SpecterConfig {
        callback_url: format!("http://{addr}/"),
        sleep_delay_ms: 0,
        sleep_jitter: 0,
        ..SpecterConfig::default()
    };
    let mut agent = SpecterAgent::new(config).expect("create agent");

    agent.run().await.expect("run");

    let callbacks = server.join().expect("server thread");
    assert_eq!(callbacks.len(), 2, "expected 2 callbacks from shell command");

    // Callback 0: proc_create info.
    let cb0 = &callbacks[0];
    assert_eq!(
        cb0.command_id,
        u32::from(DemonCommand::CommandProc),
        "first callback must be CommandProc"
    );
    assert_eq!(cb0.request_id, 100);
    // Payload starts with a subcommand (LE u32 = Create = 4).
    let subcmd = le_u32(&cb0.payload, 0);
    assert_eq!(subcmd, u32::from(DemonProcessCommand::Create));

    // Callback 1: captured output.
    let cb1 = &callbacks[1];
    assert_eq!(
        cb1.command_id,
        u32::from(DemonCommand::CommandOutput),
        "second callback must be CommandOutput"
    );
    assert_eq!(cb1.request_id, 100);
    // Output payload is a LE-length-prefixed byte slice.
    let (output_bytes, _) = le_bytes(&cb1.payload, 0);
    let output = std::str::from_utf8(output_bytes).expect("output must be UTF-8");
    assert!(
        output.contains("specter-ok"),
        "captured output must contain 'specter-ok', got: {output:?}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 4: Filesystem — Dir + GetPwd via run()
//
// Note: CommandFs only dispatches GetPwd, Cd, and Dir.  Other subcommands
// (Cat, Download, Upload, …) return Ignore and produce no callback.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_4_filesystem_dir_and_getpwd() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let fs_tasks = vec![
        (u32::from(DemonCommand::CommandFs), 200_u32, build_fs_dir_payload("/tmp")),
        (u32::from(DemonCommand::CommandFs), 201_u32, build_fs_getpwd_payload()),
    ];
    // Each Fs task → 1 Respond callback (2 total).
    let (server, addr) = spawn_mock_server(listener, fs_tasks, 2);

    let config = SpecterConfig {
        callback_url: format!("http://{addr}/"),
        sleep_delay_ms: 0,
        sleep_jitter: 0,
        ..SpecterConfig::default()
    };
    let mut agent = SpecterAgent::new(config).expect("create agent");

    agent.run().await.expect("run");

    let callbacks = server.join().expect("server thread");
    assert_eq!(callbacks.len(), 2, "expected 2 callbacks from Dir + GetPwd tasks");

    // Callback 0: Dir listing for /tmp.
    let cb0 = &callbacks[0];
    assert_eq!(cb0.command_id, u32::from(DemonCommand::CommandFs));
    assert_eq!(cb0.request_id, 200);
    let subcmd = le_u32(&cb0.payload, 0);
    assert_eq!(subcmd, u32::from(DemonFilesystemCommand::Dir), "Dir subcommand must be 1");

    // Callback 1: GetPwd result — non-empty working directory.
    let cb1 = &callbacks[1];
    assert_eq!(cb1.command_id, u32::from(DemonCommand::CommandFs));
    assert_eq!(cb1.request_id, 201);
    let subcmd = le_u32(&cb1.payload, 0);
    assert_eq!(subcmd, u32::from(DemonFilesystemCommand::GetPwd), "GetPwd subcommand must be 9");
    let (pwd, _) = le_utf16(&cb1.payload, 4);
    assert!(!pwd.is_empty(), "GetPwd must return a non-empty working directory path");
}

// ---------------------------------------------------------------------------
// Scenario 5: Process list — CommandProcList via run()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_5_process_list_contains_own_pid() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let proc_tasks =
        vec![(u32::from(DemonCommand::CommandProcList), 300_u32, build_proc_list_payload())];
    // ProcList → 1 Respond callback.
    let (server, addr) = spawn_mock_server(listener, proc_tasks, 1);

    let config = SpecterConfig {
        callback_url: format!("http://{addr}/"),
        sleep_delay_ms: 0,
        sleep_jitter: 0,
        ..SpecterConfig::default()
    };
    let mut agent = SpecterAgent::new(config).expect("create agent");

    agent.run().await.expect("run");

    let callbacks = server.join().expect("server thread");
    assert_eq!(callbacks.len(), 1, "expected 1 callback from ProcList task");

    let cb = &callbacks[0];
    assert_eq!(cb.command_id, u32::from(DemonCommand::CommandProcList));
    assert_eq!(cb.request_id, 300);

    // Response payload (LE): process_ui_flag(4) + repeated entries.
    // Each entry: utf16le(name) + pid(4) + is_wow64(4) + ppid(4) +
    //             session_id(4) + num_threads(4) + utf16le(user).
    let _process_ui = le_u32(&cb.payload, 0);
    let our_pid = std::process::id();
    let mut offset = 4;
    let mut found_self = false;

    while offset < cb.payload.len() {
        let (_name, next) = le_utf16(&cb.payload, offset);
        let pid = le_u32(&cb.payload, next);
        let _is_wow64 = le_u32(&cb.payload, next + 4);
        let _ppid = le_u32(&cb.payload, next + 8);
        let _session = le_u32(&cb.payload, next + 12);
        let _threads = le_u32(&cb.payload, next + 16);
        let (_user, after_user) = le_utf16(&cb.payload, next + 20);
        offset = after_user;

        if pid == our_pid {
            found_self = true;
            break;
        }
    }

    assert!(found_self, "process list must contain own PID {our_pid}");
}

// ---------------------------------------------------------------------------
// Scenario 6: Process grep — CommandProc::Grep via run()
//
// Note: CommandProc::Grep returns a single Respond callback (not MultiRespond),
// with the matching process list inline in the payload.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_6_process_grep_empty_needle_matches_own_pid() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let proc_tasks =
        vec![(u32::from(DemonCommand::CommandProc), 400_u32, build_proc_grep_payload(""))];
    // Proc::Grep → 1 Respond callback with the matching process list.
    let (server, addr) = spawn_mock_server(listener, proc_tasks, 1);

    let config = SpecterConfig {
        callback_url: format!("http://{addr}/"),
        sleep_delay_ms: 0,
        sleep_jitter: 0,
        ..SpecterConfig::default()
    };
    let mut agent = SpecterAgent::new(config).expect("create agent");

    agent.run().await.expect("run");

    let callbacks = server.join().expect("server thread");
    assert_eq!(callbacks.len(), 1, "expected 1 callback from Proc::Grep");

    // The single callback: CommandProc with grep results embedded.
    let cb = &callbacks[0];
    assert_eq!(cb.command_id, u32::from(DemonCommand::CommandProc));
    assert_eq!(cb.request_id, 400);

    // Payload (LE): subcommand(4) + repeated [utf16(name) + pid(4) + ppid(4) + utf16(user) + arch(4)].
    let subcmd = le_u32(&cb.payload, 0);
    assert_eq!(subcmd, u32::from(DemonProcessCommand::Grep));

    let our_pid = std::process::id();
    let mut offset = 4;
    let mut found_self = false;

    while offset < cb.payload.len() {
        let (_name, next) = le_utf16(&cb.payload, offset);
        let pid = le_u32(&cb.payload, next);
        let _ppid = le_u32(&cb.payload, next + 4);
        let (_user, next2) = le_utf16(&cb.payload, next + 8);
        let _arch = le_u32(&cb.payload, next2);
        offset = next2 + 4;

        if pid == our_pid {
            found_self = true;
            break;
        }
    }

    assert!(found_self, "grep process list must contain own PID {our_pid}");
}

// ---------------------------------------------------------------------------
// Scenario 7: Sleep command + exit — CTR advances through run() loop
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_7_sleep_command_then_exit() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    // Sleep task updates the config and echoes the new values back → 1 callback.
    let sleep_tasks =
        vec![(u32::from(DemonCommand::CommandSleep), 500_u32, build_sleep_payload(10, 5))];
    let (server, addr) = spawn_mock_server(listener, sleep_tasks, 1);

    let config = SpecterConfig {
        callback_url: format!("http://{addr}/"),
        sleep_delay_ms: 0,
        sleep_jitter: 0,
        ..SpecterConfig::default()
    };
    let mut agent = SpecterAgent::new(config).expect("create agent");

    agent.run().await.expect("run");

    let callbacks = server.join().expect("server thread");
    assert_eq!(callbacks.len(), 1, "sleep must echo new values back in 1 callback");

    // Verify the sleep echo: LE u32 delay_ms + LE u32 jitter_pct.
    let cb = &callbacks[0];
    assert_eq!(cb.command_id, u32::from(DemonCommand::CommandSleep));
    assert_eq!(cb.request_id, 500);
    assert_eq!(cb.payload.len(), 8, "sleep echo payload is 8 bytes (delay + jitter)");
    let echoed_delay = le_u32(&cb.payload, 0);
    let echoed_jitter = le_u32(&cb.payload, 4);
    assert_eq!(echoed_delay, 10, "echoed delay must match the sent value");
    assert_eq!(echoed_jitter, 5, "echoed jitter must match the sent value");
}
