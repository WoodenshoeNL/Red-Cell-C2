"""
Archon / ECDH Windows check-in triage helpers (scenario 17).

Call :func:`log_archon_ecdh_prelude` right after the HTTP listener is started, and
:func:`format_archon_checkin_timeout_diagnostics` when :func:`deploy_and_checkin`
times out to print actionable context (``callback_host``, clock comparison,
``Test-NetConnection`` to the C2).
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any
from urllib.parse import urlparse

__all__ = [
    "format_archon_checkin_timeout_diagnostics",
    "log_archon_ecdh_prelude",
]


def _teamserver_host_from_cli(cli: Any) -> str | None:
    """Return hostname from *cli.server* (``https://host:port``) or None."""
    raw = getattr(cli, "server", None) or ""
    if not raw:
        return None
    u = urlparse(raw)
    if u.hostname:
        return u.hostname
    m = re.match(r"^[^:/]+", raw)
    return m.group(0) if m else None


def log_archon_ecdh_prelude(ctx: Any, listener_name: str, port: int) -> None:
    """Print one-time ECDH/Network context after the HTTP listener is up."""
    print(f"  [archon][ecdh] listener_name={listener_name!r} http_port={port}")
    env = getattr(ctx, "env", None) or {}
    server = env.get("server", {}) or {}
    cb = server.get("callback_host")
    if cb:
        print(
            f"  [archon][ecdh] server.callback_host={cb!r} "
            f"(baked into payload; agent should call http://{cb}:{port}/...)"
        )
    else:
        print(
            "  [archon][ecdh] WARNING: server.callback_host is not set in env.toml — "
            "the teamserver may bake 127.0.0.1 into the payload. Use [server].callback_host "
            "with the address the *Windows* agent uses to reach this teamserver."
        )
    th = _teamserver_host_from_cli(ctx.cli) if hasattr(ctx, "cli") and ctx.cli else None
    if th:
        print(
            f"  [archon][ecdh] teamserver (operator) URL host={th!r} — ensure routing/firewall allows "
            f"outbound {cb or th}:{port} from the Windows VM to the C2 (see Test-NetConnection on failure)."
        )
    print(
        "  [archon][ecdh] registration replay window is 300s; large clock skew between Windows and "
        "the teamserver fails ECDH open (see teamserver WARN: timestamp outside replay window)."
    )


def _try_windows_netstat(target: Any, run_remote: Any) -> str:
    """Capture active/pending TCP connections on the Windows target (triage probe).

    Returns a summary string suitable for embedding in the triage report.
    Never raises — any error is returned as a descriptive message.
    """
    try:
        # Show ESTABLISHED and SYN_SENT rows (the ones archon.exe should produce).
        # /n = numeric, /o = owner PID.
        cmd = (
            "powershell -NoProfile -Command \""
            "netstat -n -o | Where-Object { $_ -match 'ESTAB|SYN_SENT|SYN_RCVD' }"
            "\""
        )
        out = run_remote(target, cmd, timeout=20)
        return out.strip() if out.strip() else "(no ESTABLISHED/SYN connections visible)"
    except Exception as e:  # noqa: BLE001
        return f"netstat probe failed: {e}"


def _try_windows_defender_events(target: Any, run_remote: Any) -> str:
    """Check Windows Defender event log for recent AV threat/quarantine events.

    Event IDs 1116/1117/1118 indicate Defender detected, quarantined, or removed
    a threat.  Any of these near the sc17 run window confirms H2 (Defender AV).

    Returns a summary string.  Never raises.
    """
    try:
        script = (
            "Get-WinEvent -ProviderName 'Microsoft-Windows-Windows Defender' "
            "-MaxEvents 20 -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Id -in @(1116, 1117, 1118) } | "
            "ForEach-Object { $_.TimeCreated.ToString('o') + ' [' + $_.Id + '] ' + $_.Message.Split([Environment]::NewLine)[0] }"
        )
        cmd = f"powershell -NoProfile -Command \"{script}\""
        out = run_remote(target, cmd, timeout=30)
        return out.strip() if out.strip() else "(no Defender threat events in last 20 entries)"
    except Exception as e:  # noqa: BLE001
        return f"Defender event log probe failed: {e}"


def format_archon_checkin_timeout_diagnostics(
    ctx: Any,
    target: Any,
    listener_port: int,
    exc: BaseException,
) -> str:
    """Build a multi-line string to print after a check-in :class:`lib.wait.TimeoutError`."""
    lines: list[str] = [
        "=== Archon check-in timeout — triage (scenario 17) ===",
        f"{type(exc).__name__}: {exc}",
        f"Harness UTC now: {_dt.datetime.now(_dt.timezone.utc).isoformat()}",
    ]

    env = getattr(ctx, "env", None) or {}
    server = env.get("server", {}) or {}
    cb = server.get("callback_host")
    th = _teamserver_host_from_cli(ctx.cli) if hasattr(ctx, "cli") and ctx.cli else None
    probe_host = cb or th
    if probe_host:
        lines.append(
            f"Connectivity probe target: {probe_host!r} TCP/{listener_port} "
            f"(callback_host or operator host)"
        )
    else:
        lines.append("Could not determine callback/teamserver host for connectivity hints.")

    try:
        from lib.deploy import run_remote

        win_utc = run_remote(
            target,
            'powershell -NoProfile -Command "[DateTimeOffset]::UtcNow.ToString(\\"o\\")"',
            timeout=20,
        )
        lines.append(f"Windows target UTC (PowerShell): {win_utc}")
    except Exception as e:  # noqa: BLE001 — triage must never raise
        lines.append(f"Windows UTC probe (SSH) failed: {e}")

    if probe_host:
        # -InformationLevel Quiet returns $true/$false without slow ICMP ping phase.
        tnc = (
            "powershell -NoProfile -Command "
            f"\"(Test-NetConnection -ComputerName '{probe_host}' -Port {listener_port} "
            f"-InformationLevel Quiet -WarningAction SilentlyContinue)\""
        )
        try:
            from lib.deploy import run_remote

            tnc_out = run_remote(target, tnc, timeout=45)
            lines.append(f"Test-NetConnection (TCP reachable): {tnc_out}")
        except Exception as e:  # noqa: BLE001
            lines.append(f"Test-NetConnection failed: {e}")

    # Netstat: shows whether archon.exe is attempting TCP connections at all.
    # If ESTABLISHED/SYN rows appear → traffic leaving host but server not receiving.
    # If no rows → H1 (Firewall) or H2 (AV suspended process) or H3 (WinHTTP init fail).
    try:
        from lib.deploy import run_remote as _run_remote

        lines.append("--- netstat (active/pending TCP) ---")
        lines.append(_try_windows_netstat(target, _run_remote))
    except Exception as e:  # noqa: BLE001
        lines.append(f"netstat section failed: {e}")

    # Defender event log: IDs 1116/1117/1118 confirm H2 (AV quarantine).
    try:
        from lib.deploy import run_remote as _run_remote2

        lines.append("--- Windows Defender threat events (last 20 entries) ---")
        lines.append(_try_windows_defender_events(target, _run_remote2))
    except Exception as e:  # noqa: BLE001
        lines.append(f"Defender event section failed: {e}")

    return "\n".join(lines) + "\n"
