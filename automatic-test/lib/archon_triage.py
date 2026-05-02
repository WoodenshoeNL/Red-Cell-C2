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
    "log_archon_checkin_wait_netstat",
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


def _try_windows_workdir_processes(target: Any, run_remote: Any) -> str:
    """List live processes launched from *target.work_dir* (best-effort).

    Primary query uses ``ExecutablePath`` which is accurate but returns NULL for
    processes launched under S4U Task Scheduler sessions (a WMI limitation on
    Windows 10 — the kernel does not expose the path via WMI for those tokens).
    A fallback query searches by process name pattern (``agent-*.exe``) to catch
    S4U-launched payloads that the primary filter misses.
    """
    work_dir = str(getattr(target, "work_dir", "") or "").strip()
    if not work_dir:
        return "(target.work_dir unavailable)"
    escaped = work_dir.replace("'", "''")
    try:
        script = (
            "$wd = '"
            + escaped
            + "'; "
            "$rows = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
            "Where-Object { $_.ExecutablePath -like ($wd + '\\*') } | "
            "ForEach-Object { "
            "  $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue; "
            "  $ownerText = if ($owner -and $owner.User) { $owner.Domain + '\\' + $owner.User } else { '(owner unavailable)' }; "
            "  '{0}|{1}|{2}|{3}' -f $_.ProcessId, $_.Name, $ownerText, $_.ExecutablePath "
            "}; "
            "if ($rows) { $rows } else { "
            # S4U processes have NULL ExecutablePath in WMI — fall back to name pattern.
            "  $fb = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
            "  Where-Object { $_.Name -like 'agent-*.exe' } | "
            "  ForEach-Object { "
            "    $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue; "
            "    $ot = if ($o -and $o.User) { $o.Domain + '\\' + $o.User } else { '(owner unavailable)' }; "
            "    '{0}|{1}|{2}|(fallback/no-ExePath)' -f $_.ProcessId, $_.Name, $ot "
            "  }; "
            "  if ($fb) { $fb } "
            "} "
        )
        cmd = f"powershell -NoProfile -Command \"{script}\""
        out = run_remote(target, cmd, timeout=30)
        return out.strip() if out.strip() else "(no live processes from target.work_dir)"
    except Exception as e:  # noqa: BLE001
        return f"work_dir process probe failed: {e}"


def _try_windows_appcrash_events(target: Any, run_remote: Any, exe_leaf: str) -> str:
    """Check Windows Application event log for APPCRASH events for *exe_leaf* (EventID 1000).

    An Application Error entry confirms the agent process crashed (unhandled exception)
    rather than simply failing to make network connections.  The exit-code field inside
    the crash record often points to the faulting module.

    Returns a summary string.  Never raises.
    """
    try:
        leaf_q = exe_leaf.replace("'", "''")
        script = (
            "Get-WinEvent -LogName 'Application' -MaxEvents 30 "
            "-ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.Id -eq 1000 -and $_.Message -match '{leaf_q}' }} | "
            "ForEach-Object { $_.TimeCreated.ToString('o') + ' [1000] ' + $_.Message.Split([Environment]::NewLine)[0] }"
        )
        cmd = f"powershell -NoProfile -Command \"{script}\""
        out = run_remote(target, cmd, timeout=30)
        return out.strip() if out.strip() else f"(no APPCRASH entries for {exe_leaf!r} in last 30 Application events)"
    except Exception as e:  # noqa: BLE001
        return f"APPCRASH event probe failed: {e}"


def _try_verify_np_exclusion(target: Any, run_remote: Any, ip_address: str) -> str:
    """Verify that *ip_address* is present in Defender's ExclusionIpAddress list.

    Confirms that ``defender_network_protection_exclusion`` actually took effect before
    the agent was launched.  An absent entry means the Network Protection block is still
    active and WinHTTP connections from S4U processes will be silently dropped.

    Returns a summary string.  Never raises.
    """
    try:
        ip_q = ip_address.replace("'", "''")
        script = (
            "$excl = (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionIpAddress; "
            f"if ($excl -contains '{ip_q}') {{ Write-Output 'PRESENT' }} "
            f"else {{ Write-Output ('ABSENT — current list: ' + ($excl -join ', ')) }}"
        )
        cmd = f"powershell -NoProfile -Command \"{script}\""
        out = run_remote(target, cmd, timeout=20)
        return out.strip() if out.strip() else "(Get-MpPreference returned no output)"
    except Exception as e:  # noqa: BLE001
        return f"MpPreference ExclusionIpAddress probe failed: {e}"


def _try_windows_network_protection_events(target: Any, run_remote: Any) -> str:
    """Check Windows Defender Network Protection block events (IDs 1125/1127/1128).

    Event ID 1125: Network protection blocked a network connection (enforce mode).
    Event ID 1127: Network protection audited a connection (audit mode — would block).
    Event ID 1128: Network protection blocked a connection (enforce mode, alt schema).

    These events explain the S4U no-TCP symptom: WinHTTP gets an immediate internal
    error before any SYN packet is sent, so netstat shows zero rows for the C2 port
    even though Test-NetConnection from PowerShell succeeds.

    Returns a summary string.  Never raises.
    """
    try:
        script = (
            "Get-WinEvent -ProviderName 'Microsoft-Windows-Windows Defender' "
            "-MaxEvents 30 -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Id -in @(1125, 1127, 1128) } | "
            "ForEach-Object { $_.TimeCreated.ToString('o') + ' [' + $_.Id + '] ' + $_.Message.Split([Environment]::NewLine)[0] }"
        )
        cmd = f"powershell -NoProfile -Command \"{script}\""
        out = run_remote(target, cmd, timeout=30)
        return out.strip() if out.strip() else "(no Network Protection block events in last 30 entries)"
    except Exception as e:  # noqa: BLE001
        return f"Network Protection event log probe failed: {e}"


def log_archon_checkin_wait_netstat(target: Any, c2_port: int, tag: str = "mid-wait") -> None:
    """Print netstat lines mentioning *c2_port* during agent check-in wait (best-effort).

    Filters remote output so transient ``SYN_SENT`` rows to the listener are visible
    without dumping the full netstat table each tick.
    """
    try:
        from lib.deploy import run_remote

        cmd = (
            "powershell -NoProfile -Command \""
            f"netstat -n -o | Where-Object {{ $_ -match ':{int(c2_port)}' }}"
            "\""
        )
        out = run_remote(target, cmd, timeout=15)
        body = out.strip() if out.strip() else f"(no rows mentioning :{c2_port})"
        print(f"  [archon][netstat][{tag}] port {c2_port}:")
        for line in body.splitlines()[:30]:
            print(f"    {line.strip()}")
    except Exception as e:  # noqa: BLE001
        print(f"  [archon][netstat][{tag}] probe failed: {e}")


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

    # Network Protection block events: IDs 1125/1127/1128.
    # Explains the S4U no-TCP symptom (zero netstat rows despite process running).
    try:
        from lib.deploy import run_remote as _run_remote4

        lines.append("--- Defender Network Protection block events (IDs 1125/1127/1128) ---")
        lines.append(_try_windows_network_protection_events(target, _run_remote4))
    except Exception as e:  # noqa: BLE001
        lines.append(f"Network Protection event section failed: {e}")

    try:
        from lib.deploy import run_remote as _run_remote3

        lines.append("--- live processes from target.work_dir ---")
        lines.append(_try_windows_workdir_processes(target, _run_remote3))
    except Exception as e:  # noqa: BLE001
        lines.append(f"work_dir process section failed: {e}")

    # APPCRASH events: EventID 1000 for the agent exe confirms a crash (unhandled
    # exception) as opposed to a clean-exit or network-block scenario.
    if probe_host:
        try:
            from lib.deploy import run_remote as _run_remote5

            # The exe name pattern is "agent-<hex>.exe" — probe all of them.
            exe_leaf = "agent-"
            lines.append("--- APPCRASH events for agent-*.exe (Application EventID 1000) ---")
            lines.append(_try_windows_appcrash_events(target, _run_remote5, exe_leaf))
        except Exception as e:  # noqa: BLE001
            lines.append(f"APPCRASH event section failed: {e}")

    # MpPreference ExclusionIpAddress verification: confirms the Network Protection
    # IP exclusion was applied before launch.  ABSENT means NP is still blocking.
    if probe_host:
        try:
            from lib.deploy import run_remote as _run_remote6

            lines.append(f"--- MpPreference ExclusionIpAddress ({probe_host}) ---")
            lines.append(_try_verify_np_exclusion(target, _run_remote6, probe_host))
        except Exception as e:  # noqa: BLE001
            lines.append(f"MpPreference exclusion verification failed: {e}")

    return "\n".join(lines) + "\n"
