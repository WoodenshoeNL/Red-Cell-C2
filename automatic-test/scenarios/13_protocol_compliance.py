"""
Scenario 13: Binary protocol compliance verification

Sends crafted raw Demon protocol packets directly to an HTTP listener and
validates that the teamserver accepts or rejects them according to the
wire format specification.  No target machines are required — every packet
is built entirely in Python using only the standard library.

Protocol under test
-------------------
Every Demon packet consists of a 12-byte header followed by a payload:

  Header (12 bytes, big-endian):
    [0:4]   size   = 8 + len(payload)   # excludes the 4-byte size field itself
    [4:8]   magic  = 0xDEADBEEF
    [8:12]  agent_id

  DEMON_INIT payload (command 99):
    [0:4]   command_id = 99
    [4:8]   request_id (any u32)
    [8:40]  AES-256 session key    (32 bytes)
    [40:56] AES CTR IV              (16 bytes)
    [56:]   AES-256-CTR(key, iv, offset=0, metadata)

  Metadata (plaintext before encryption):
    agent_id                u32 BE
    hostname                u32-prefixed UTF-8
    username                u32-prefixed UTF-8
    domain_name             u32-prefixed UTF-8
    internal_ip             u32-prefixed UTF-8
    process_path            u32-prefixed UTF-16-LE
    process_pid             u32 BE
    process_tid             u32 BE
    process_ppid            u32 BE
    process_arch            u32 BE
    elevated                u32 BE  (0 or 1)
    base_address            u64 BE
    os_major                u32 BE
    os_minor                u32 BE
    os_product_type         u32 BE
    os_service_pack         u32 BE
    os_build                u32 BE
    os_arch                 u32 BE
    sleep_delay             u32 BE  (seconds)
    sleep_jitter            u32 BE  (percent)
    kill_date               u64 BE  (unix epoch, 0 = none)
    working_hours           i32 BE  (signed, 0 = no restriction)
    extension_flags         u32 BE  (INIT_EXT_MONOTONIC_CTR = 0x1)

  DEMON_INIT server response:
    4 bytes = AES-256-CTR(key, iv, offset=0, agent_id.to_le_bytes())

  GET_JOB callback payload (command 1):
    [0:4]   command_id = 1
    [4:8]   request_id (any u32)
    [8:]    AES-256-CTR(key, iv, offset=post_init,
                u32be(0))   # length-prefixed empty payload

  GET_JOB server response (no jobs queued):
    empty body (HTTP 200, Content-Length: 0)

AES note
--------
The teamserver rejects legacy CTR sessions by default (AllowLegacyCtr = false
in shipped Demon profiles).  These probes therefore set the
INIT_EXT_MONOTONIC_CTR extension flag in DEMON_INIT, which switches the agent
into monotonic CTR mode: the shared block offset advances by
`ctr_blocks_for_len(len)` after every encrypted send and after the init ACK.
The probes intentionally omit INIT_EXT_SEQ_PROTECTED so callbacks do not need
the 8-byte sequence prefix — this keeps the wire format minimal while still
exercising the modern post-hardening protocol.

AES-256-CTR is implemented by calling `openssl enc -aes-256-ctr` via
subprocess — the only way to do AES in pure-Python without adding a third-
party dependency.  Block-offset support is layered on top by deriving a new
starting counter as `(IV as big-endian u128) + block_offset`, mirroring the
`encrypt_agent_data_at_offset` helper in `common/src/crypto`.
"""

from __future__ import annotations

DESCRIPTION = "Binary protocol compliance: Demon wire format validation"

import os
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import urlparse

from lib.wait import wait_for_port


# ── Wire format constants ────────────────────────────────────────────────────

DEMON_MAGIC = 0xDEAD_BEEF
DEMON_INIT_CMD = 99
DEMON_GET_JOB_CMD = 1

AES_KEY_LEN = 32
AES_IV_LEN = 16
AES_BLOCK_LEN = 16

# Extension flag requesting monotonic CTR mode in DEMON_INIT.  Mirrors
# `INIT_EXT_MONOTONIC_CTR` in `common/src/agent_protocol.rs`.  We deliberately
# do not also set `INIT_EXT_SEQ_PROTECTED`: that would require every callback
# plaintext to be prefixed with an 8-byte LE sequence number, which is not
# needed to exercise the protocol-compliance checks below.
INIT_EXT_MONOTONIC_CTR = 1 << 0


# ── Crypto helpers (openssl subprocess, no third-party Python deps) ──────────

def _aes_256_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-256-CTR using the system openssl binary.

    Encrypt or decrypt `data` starting at CTR block offset 0.
    CTR mode is its own inverse, so one function covers both directions.
    """
    if not data:
        return b""
    result = subprocess.run(
        [
            "openssl", "enc", "-aes-256-ctr", "-nosalt",
            "-K", key.hex(),
            "-iv", iv.hex(),
        ],
        input=data,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"openssl AES-CTR failed (exit {result.returncode}): "
            f"{result.stderr.decode(errors='replace')}"
        )
    return result.stdout


def _aes_256_ctr_at_offset(key: bytes, iv: bytes, block_offset: int, data: bytes) -> bytes:
    """AES-256-CTR starting `block_offset` 16-byte blocks past `iv`.

    Mirrors `encrypt_agent_data_at_offset` in `common/src/crypto`: the IV is
    treated as a big-endian u128 counter, `block_offset` is added (mod 2^128),
    and the result is used as the starting AES-CTR counter.
    """
    if block_offset == 0:
        return _aes_256_ctr(key, iv, data)
    counter = (int.from_bytes(iv, "big") + block_offset) & ((1 << 128) - 1)
    new_iv = counter.to_bytes(16, "big")
    return _aes_256_ctr(key, new_iv, data)


def _ctr_blocks_for_len(byte_len: int) -> int:
    """Number of full AES-CTR blocks consumed by a `byte_len`-byte payload.

    Matches the Rust helper `ctr_blocks_for_len` in `common/src/crypto`: a
    1-byte payload still consumes one full 16-byte keystream block.
    """
    if byte_len == 0:
        return 0
    return (byte_len + AES_BLOCK_LEN - 1) // AES_BLOCK_LEN


# ── Binary packing helpers ───────────────────────────────────────────────────

def _u32be(n: int) -> bytes:
    return struct.pack(">I", n)


def _i32be(n: int) -> bytes:
    return struct.pack(">i", n)


def _u64be(n: int) -> bytes:
    return struct.pack(">Q", n)


def _u32le(n: int) -> bytes:
    return struct.pack("<I", n)


def _len_prefix_utf8(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return _u32be(len(encoded)) + encoded


def _len_prefix_utf16le(s: str) -> bytes:
    encoded = s.encode("utf-16-le")
    return _u32be(len(encoded)) + encoded


def _len_prefix_utf16be(s: str) -> bytes:
    """Encode as UTF-16-BE — used only in negative tests to verify rejection."""
    encoded = s.encode("utf-16-be")
    return _u32be(len(encoded)) + encoded


# ── Packet builders ──────────────────────────────────────────────────────────

def _build_envelope(agent_id: int, payload: bytes) -> bytes:
    """Wrap a payload in the 12-byte Demon transport header.

    Header layout (big-endian):
      [0:4]   size   = 8 + len(payload)
      [4:8]   magic  = 0xDEADBEEF
      [8:12]  agent_id
    """
    size = len(payload) + 8
    return _u32be(size) + _u32be(DEMON_MAGIC) + _u32be(agent_id) + payload


def _build_demon_init_metadata(agent_id: int) -> bytes:
    """Construct the plaintext DEMON_INIT metadata block."""
    buf = b""
    buf += _u32be(agent_id)                           # agent_id (must match header)
    buf += _len_prefix_utf8("probe-host")             # hostname
    buf += _len_prefix_utf8("probe-user")             # username
    buf += _len_prefix_utf8("WORKGROUP")              # domain_name
    buf += _len_prefix_utf8("10.0.0.1")               # internal_ip
    buf += _len_prefix_utf16le("C:\\probe\\agent.exe")  # process_path (UTF-16-LE)
    buf += _u32be(1000)                               # process_pid
    buf += _u32be(1001)                               # process_tid
    buf += _u32be(999)                                # process_ppid
    buf += _u32be(2)                                  # process_arch (x64)
    buf += _u32be(0)                                  # elevated (false)
    buf += _u64be(0x0040_0000)                        # base_address
    buf += _u32be(10)                                 # os_major
    buf += _u32be(0)                                  # os_minor
    buf += _u32be(1)                                  # os_product_type
    buf += _u32be(0)                                  # os_service_pack
    buf += _u32be(22621)                              # os_build (Win 11 22H2)
    buf += _u32be(9)                                  # os_arch (AMD64)
    buf += _u32be(30)                                 # sleep_delay (seconds)
    buf += _u32be(10)                                 # sleep_jitter (%)
    buf += _u64be(0)                                  # kill_date (0 = none)
    buf += _i32be(0)                                  # working_hours (no restriction)
    # Extension flags: opt in to monotonic CTR mode so the teamserver accepts
    # the registration without `AllowLegacyCtr = true`.
    buf += _u32be(INIT_EXT_MONOTONIC_CTR)
    return buf


def _build_demon_init_metadata_wrong_endian(agent_id: int) -> bytes:
    """Construct a DEMON_INIT metadata block with process_path in wrong (BE) endianness.

    This produces a packet that the teamserver will accept (the structure is
    valid), but the decoded process_path will be garbled because the server
    expects UTF-16-LE.
    """
    buf = b""
    buf += _u32be(agent_id)
    buf += _len_prefix_utf8("probe-host-be")
    buf += _len_prefix_utf8("probe-user-be")
    buf += _len_prefix_utf8("WORKGROUP")
    buf += _len_prefix_utf8("10.0.0.2")
    buf += _len_prefix_utf16be("C:\\probe\\agent.exe")  # WRONG endianness
    buf += _u32be(2000)
    buf += _u32be(2001)
    buf += _u32be(1999)
    buf += _u32be(2)
    buf += _u32be(0)
    buf += _u64be(0x0040_0000)
    buf += _u32be(10)
    buf += _u32be(0)
    buf += _u32be(1)
    buf += _u32be(0)
    buf += _u32be(22621)
    buf += _u32be(9)
    buf += _u32be(30)
    buf += _u32be(10)
    buf += _u64be(0)
    buf += _i32be(0)
    # Same monotonic-CTR opt-in as the well-formed metadata; without it the
    # teamserver rejects the packet before it ever inspects process_path.
    buf += _u32be(INIT_EXT_MONOTONIC_CTR)
    return buf


def _build_demon_init_packet(agent_id: int, key: bytes, iv: bytes) -> bytes:
    """Build a complete, well-formed DEMON_INIT packet."""
    metadata = _build_demon_init_metadata(agent_id)
    encrypted = _aes_256_ctr(key, iv, metadata)
    request_id = 1
    payload = (
        _u32be(DEMON_INIT_CMD)
        + _u32be(request_id)
        + key
        + iv
        + encrypted
    )
    return _build_envelope(agent_id, payload)


def _build_demon_init_reconnect_packet(agent_id: int) -> bytes:
    """Build a DEMON_INIT reconnect probe (empty payload after cmd+req_id).

    A reconnect probe is sent by an already-registered agent to re-synchronise
    with the teamserver.  The payload is only the command and request_id fields
    with no key material or encrypted metadata.
    """
    request_id = 2
    payload = _u32be(DEMON_INIT_CMD) + _u32be(request_id)
    return _build_envelope(agent_id, payload)


def _build_get_job_packet(agent_id: int) -> bytes:
    """Build a GET_JOB callback packet (heartbeat — no sub-packages).

    GET_JOB uses the batched format: the encrypted body is a stream of
    (command_id, request_id, payload) sub-packages.  A heartbeat with no
    outbound data has an *empty* encrypted body — no length prefix, because
    the parser would misinterpret it as a truncated sub-command.
    """
    request_id = 3
    payload = (
        _u32be(DEMON_GET_JOB_CMD)
        + _u32be(request_id)
    )
    return _build_envelope(agent_id, payload)


def _build_demon_init_packet_wrong_endian(agent_id: int, key: bytes, iv: bytes) -> bytes:
    """Build a DEMON_INIT packet with process_path encoded as UTF-16-BE (wrong).

    The teamserver will accept the packet (structurally valid), but the decoded
    process_path will be garbled because the parser expects UTF-16-LE.
    """
    metadata = _build_demon_init_metadata_wrong_endian(agent_id)
    encrypted = _aes_256_ctr(key, iv, metadata)
    request_id = 1
    payload = (
        _u32be(DEMON_INIT_CMD)
        + _u32be(request_id)
        + key
        + iv
        + encrypted
    )
    return _build_envelope(agent_id, payload)


# ── HTTP helpers ─────────────────────────────────────────────────────────────

def _post_raw(url: str, body: bytes, timeout: int = 10) -> tuple[int, bytes]:
    """POST raw bytes to `url`.  Returns (status_code, response_body).

    urllib treats 4xx/5xx as HTTPError; we catch them and return the
    status code so callers can assert on rejection responses too.
    """
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/octet-stream")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


# ── Listener readiness ───────────────────────────────────────────────────────

def _wait_for_tcp(host: str, port: int, timeout: int = 15) -> None:
    """Block until `host:port` accepts TCP connections or `timeout` seconds pass."""
    wait_for_port(host, port, timeout=float(timeout))


# ── URL helpers ──────────────────────────────────────────────────────────────

def _server_host(env: dict) -> str:
    """Extract the hostname/IP from the teamserver URL in env.toml."""
    for key in ("rest_url", "url"):
        raw = env.get("server", {}).get(key, "")
        if raw:
            parsed = urlparse(raw)
            if parsed.hostname:
                return parsed.hostname
    return "127.0.0.1"


# ── Individual compliance checks ─────────────────────────────────────────────

def _check(name: str, cond: bool, detail: str = "") -> None:
    """Assert `cond` is true; print a PASS/FAIL line."""
    status = "PASS" if cond else "FAIL"
    suffix = f": {detail}" if detail else ""
    print(f"    [{status}] {name}{suffix}")
    if not cond:
        raise AssertionError(f"Protocol compliance check failed — {name}{suffix}")


def _run_rejection_checks(base_url: str) -> None:
    """Verify the listener rejects malformed / non-Demon requests."""

    # ── 1. Empty body ────────────────────────────────────────────────────────
    print("  [check] empty body → 404")
    status, _ = _post_raw(base_url, b"")
    _check("empty body rejected", status == 404, f"got HTTP {status}")

    # ── 2. Body shorter than 8 bytes (cannot contain magic) ─────────────────
    print("  [check] 5-byte body → 404")
    status, _ = _post_raw(base_url, b"\x00" * 5)
    _check("5-byte body rejected", status == 404, f"got HTTP {status}")

    # ── 3. Wrong magic value ─────────────────────────────────────────────────
    print("  [check] wrong magic (0xCAFEBABE) → 404")
    # Well-formed header except magic = 0xCAFEBABE
    agent_id = 0x0000_0001
    payload = _u32be(DEMON_INIT_CMD) + _u32be(1) + b"\x00" * 8
    size = len(payload) + 8
    bad_magic_packet = (
        _u32be(size)
        + _u32be(0xCAFE_BABE)      # wrong magic
        + _u32be(agent_id)
        + payload
    )
    status, _ = _post_raw(base_url, bad_magic_packet)
    _check("wrong magic rejected", status == 404, f"got HTTP {status}")

    # ── 4. Size field mismatch ───────────────────────────────────────────────
    print("  [check] size field mismatch → 404")
    agent_id = 0x0000_0002
    payload = _u32be(DEMON_INIT_CMD) + _u32be(1) + b"\x00" * 8
    # Claim size covers 100 extra bytes that aren't there
    bad_size = len(payload) + 8 + 100
    bad_size_packet = (
        _u32be(bad_size)
        + _u32be(DEMON_MAGIC)
        + _u32be(agent_id)
        + payload
    )
    status, _ = _post_raw(base_url, bad_size_packet)
    _check("size mismatch rejected", status == 404, f"got HTTP {status}")

    # ── 5. Reserved agent_id 0x00000000 in DEMON_INIT ───────────────────────
    print("  [check] agent_id=0 in DEMON_INIT → 404")
    key = os.urandom(AES_KEY_LEN)
    iv = os.urandom(AES_IV_LEN)
    zero_id_packet = _build_demon_init_packet(0, key, iv)
    # Patch agent_id in the header to 0 (it already is, since we passed 0)
    status, _ = _post_raw(base_url, zero_id_packet)
    _check("agent_id=0 rejected", status == 404, f"got HTTP {status}")


def _run_init_handshake_check(base_url: str) -> tuple[int, bytes, bytes, int]:
    """Send a valid DEMON_INIT and verify the server returns the correct ACK.

    Returns (agent_id, key, iv, post_init_offset) for use in subsequent
    checks.  `post_init_offset` is the shared CTR block offset after the init
    handshake completes (the server advances by `ctr_blocks_for_len(ack_len)`
    when it encrypts the ACK in monotonic CTR mode).
    """
    agent_id = int.from_bytes(os.urandom(4), "big")
    # Ensure agent_id != 0 (reserved)
    while agent_id == 0:
        agent_id = int.from_bytes(os.urandom(4), "big")

    key = os.urandom(AES_KEY_LEN)
    iv = os.urandom(AES_IV_LEN)

    print(f"  [check] valid DEMON_INIT (agent_id=0x{agent_id:08X}) → 200 + ACK")
    packet = _build_demon_init_packet(agent_id, key, iv)
    status, body = _post_raw(base_url, packet)
    _check("DEMON_INIT accepted (HTTP 200)", status == 200, f"got HTTP {status}")
    _check("DEMON_INIT response non-empty", len(body) > 0, f"empty response body")

    # The init ACK is AES-256-CTR(key, iv, offset=0, agent_id.to_le_bytes()).
    # In monotonic CTR mode the server advances the shared offset by
    # `ctr_blocks_for_len(len(body))` after sending the ACK; subsequent
    # callbacks must use that advanced offset.
    expected_plaintext = _u32le(agent_id)
    actual_plaintext = _aes_256_ctr_at_offset(key, iv, 0, body)
    _check(
        "DEMON_INIT ACK decrypts to agent_id (LE)",
        actual_plaintext == expected_plaintext,
        f"got {actual_plaintext.hex()!r}, expected {expected_plaintext.hex()!r}",
    )

    post_init_offset = _ctr_blocks_for_len(len(body))
    return agent_id, key, iv, post_init_offset


def _run_reconnect_check(
    base_url: str, agent_id: int, key: bytes, iv: bytes, block_offset: int
) -> None:
    """Verify that a registered agent can send a reconnect probe.

    The reconnect ACK is encrypted at the current shared CTR offset *without*
    advancing it (see `build_reconnect_ack` in `teamserver/src/demon/ack.rs`),
    so we decrypt at `block_offset` and the agent's local offset is unchanged
    after this check.
    """
    print(f"  [check] DEMON_INIT reconnect probe → 200 + ACK")
    packet = _build_demon_init_reconnect_packet(agent_id)
    status, body = _post_raw(base_url, packet)
    _check("reconnect probe accepted (HTTP 200)", status == 200, f"got HTTP {status}")
    _check("reconnect ACK non-empty", len(body) > 0, "empty reconnect ACK")

    expected_plaintext = _u32le(agent_id)
    actual_plaintext = _aes_256_ctr_at_offset(key, iv, block_offset, body)
    _check(
        "reconnect ACK decrypts to agent_id (LE)",
        actual_plaintext == expected_plaintext,
        f"got {actual_plaintext.hex()!r}, expected {expected_plaintext.hex()!r}",
    )


def _run_get_job_check(
    base_url: str, agent_id: int
) -> None:
    """Verify that a GET_JOB poll with no queued jobs returns an empty 200."""
    print(f"  [check] GET_JOB poll (no jobs queued) → 200 + empty body")
    packet = _build_get_job_packet(agent_id)
    status, body = _post_raw(base_url, packet)
    _check("GET_JOB accepted (HTTP 200)", status == 200, f"got HTTP {status}")
    _check("GET_JOB response empty (no jobs)", len(body) == 0, f"body has {len(body)} bytes")


def _run_wrong_endian_check(base_url: str) -> int:
    """Garbled-endian DEMON_INIT: server accepts (valid structure), process_path is garbled.

    The server parses process_path as UTF-16-LE regardless of byte order, so a
    UTF-16-BE-encoded path registers successfully but with garbled content.  The
    transport layer cannot distinguish endianness — rejection would require an
    upper-layer content policy that does not exist.

    Returns the registered agent_id so the caller can clean it up.
    """
    agent_id = int.from_bytes(os.urandom(4), "big")
    while agent_id == 0:
        agent_id = int.from_bytes(os.urandom(4), "big")

    key = os.urandom(AES_KEY_LEN)
    iv = os.urandom(AES_IV_LEN)

    print(f"  [check] DEMON_INIT with UTF-16-BE process_path (garbled-path probe, agent_id=0x{agent_id:08X})")
    packet = _build_demon_init_packet_wrong_endian(agent_id, key, iv)
    status, body = _post_raw(base_url, packet)
    _check(
        "BE-encoded DEMON_INIT accepted (server cannot detect endian mismatch)",
        status == 200,
        f"got HTTP {status} with {len(body)} response bytes",
    )
    return agent_id


# ── Main entry point ─────────────────────────────────────────────────────────

def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool
    ctx.linux   — TargetConfig | None  (not used)
    ctx.windows — TargetConfig | None  (not used)

    Raises AssertionError with a descriptive message on any compliance failure.
    """
    from lib.cli import CliError, agent_kill, listener_create, listener_delete, listener_start, listener_stop

    cli = ctx.cli
    uid = uuid.uuid4().hex[:8]
    listener_name = f"test-proto-{uid}"

    # The protocol probe port can be overridden in env.toml under [listeners].
    # Default: 19090.  Choose a port that does not conflict with other scenarios.
    listener_port = ctx.env.get("listeners", {}).get("protocol_probe_port", 19090)
    server_host = _server_host(ctx.env)
    base_url = f"http://{server_host}:{listener_port}/"

    print(f"  [listener] creating HTTP listener {listener_name!r} on {server_host}:{listener_port}")
    listener_create(cli, listener_name, "http", port=listener_port, legacy_mode=True)
    listener_start(cli, listener_name)
    print("  [listener] started — waiting for port to open")
    _wait_for_tcp(server_host, listener_port, timeout=int(ctx.timeouts.listener_startup))
    print("  [listener] ready")

    agent_id = None
    wrong_endian_agent_id = None
    key = None
    iv = None
    try:
        # Phase 1: rejection checks (no valid agent registered yet)
        print("  [phase 1] rejection checks")
        _run_rejection_checks(base_url)

        # Phase 2: valid DEMON_INIT handshake
        print("  [phase 2] DEMON_INIT handshake")
        agent_id, key, iv, post_init_offset = _run_init_handshake_check(base_url)

        # Phase 3: reconnect probe (agent already registered).  The reconnect
        # ACK does not advance the shared CTR offset.
        print("  [phase 3] reconnect probe")
        _run_reconnect_check(base_url, agent_id, key, iv, post_init_offset)

        # Phase 4: GET_JOB poll (no jobs queued).  Encrypted at the post-init
        # offset; the empty response means no further offset advance.
        print("  [phase 4] GET_JOB poll")
        _run_get_job_check(base_url, agent_id)

        # Phase 5: garbled-endian probe — server accepts (transport is valid),
        # process_path stored with garbled content.
        print("  [phase 5] wrong-endian UTF-16-BE process_path (garbled-path probe)")
        wrong_endian_agent_id = _run_wrong_endian_check(base_url)

        print("  [result] all protocol compliance checks passed")

    finally:
        # Kill the synthetic agents registered during phases 2 and 5 so they do
        # not pollute the DB and confuse wait_for_agent() in later scenarios.
        for aid in (agent_id, wrong_endian_agent_id):
            if aid is not None:
                aid_hex = f"{aid:08X}"
                print(f"  [cleanup] killing synthetic agent {aid_hex}")
                try:
                    agent_kill(cli, aid_hex)
                except Exception as exc:
                    print(f"  [cleanup] agent kill failed (non-fatal): {exc}")

        print(f"  [cleanup] stopping/deleting listener {listener_name!r}")
        try:
            listener_stop(cli, listener_name)
        except Exception:
            pass
        try:
            listener_delete(cli, listener_name)
        except Exception:
            pass
        print("  [cleanup] done")
