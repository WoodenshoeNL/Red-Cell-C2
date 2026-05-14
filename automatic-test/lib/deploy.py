"""
lib/deploy.py — SSH/SCP deployment helpers for Linux and Windows targets.

Uses the system `ssh` and `scp` binaries so no extra Python dependencies
are needed. Both Linux and Windows targets are accessed via SSH
(OpenSSH for Windows — see docs/win11-ssh-setup.md).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from lib import ScenarioSkipped

logger = logging.getLogger(__name__)

_SSH_MAX_ATTEMPTS = 3
_SSH_RETRY_BACKOFF_SEC = 2

# Set by :func:`configure_deploy_timeouts` from ``config/env.toml`` ``[timeouts]``.
_SSH_CONNECT_SECS = 10
_SCP_TRANSFER_SECS = 60
_DEFAULT_REMOTE_CMD_SECS = 30

# WFP filter-pool headroom threshold.  The count is the total number of <item> tags
# in `netsh wfp show state` output, including nested items inside provider contexts,
# filter conditions, and flag arrays — not just top-level filter objects.
#
# Observed baselines on the test VM (Windows 11, firewall disabled, NP disabled):
#   Post-reboot idle:  ~4 100–4 200 nested items (providerContexts=599, filters=187)
#   Pool exhaustion:   ~6 800+ (seen before fixes; caused WSAENOBUFS / os error 10055)
#
# Threshold lowered from 5 500 to 4 800 to catch gradual accumulation earlier:
# agents fail (os error 10055) before the count reaches 5 500 because zombie
# FWPM_GENERAL_CONTEXT objects from crashed agent processes consume non-paged pool
# without adding WFP filter items.  4 800 catches growth of ~600 items above baseline
# while remaining ~2 000 items below observed exhaustion.
WFP_RESTART_THRESHOLD = 4800

# Non-paged pool bytes threshold for WFP escalation.  Used as a secondary trigger
# when the WFP item count alone does not reflect pool pressure (e.g. kernel objects
# from crashed processes — not WFP filters — fill the pool).
#
# Observed baselines (Windows 11, 16 GB RAM, firewall disabled):
#   Idle:            ~150–250 MB
#   Stressed (crash artifacts): >350 MB, causes WSAENOBUFS before WFP count reaches 4800
#
# Set to 350 MB (350_000_000 bytes).  When non-paged pool bytes exceed this value,
# mpssvc is restarted regardless of the WFP item count.
NP_POOL_BYTES_THRESHOLD = 350_000_000

# Hosts confirmed unreachable at startup by check_ssh_targets().  Per-scenario
# preflight_ssh() calls short-circuit to ScenarioSkipped for these hosts so that
# TCP-timeout retry loops (3 × ConnectTimeout s each) do not bloat the total
# run time when a VM is firewalled rather than ICMP-rejecting.
_globally_unreachable_hosts: set[str] = set()


def mark_host_unreachable(host: str) -> None:
    """Record *host* as globally unreachable so :func:`preflight_ssh` skips it immediately.

    Called by ``check_ssh_targets()`` in ``test.py`` after the startup pre-flight
    confirms a target is unreachable.  Avoids 3 × ConnectTimeout-second retry loops
    in per-scenario preflight calls when the VM is TCP-firewalled (packet drop rather
    than ICMP rejection).
    """
    _globally_unreachable_hosts.add(host)


def clear_globally_unreachable_hosts() -> None:
    """Clear the globally-unreachable registry (test helper — do not call in production)."""
    _globally_unreachable_hosts.clear()


def configure_deploy_timeouts(
    *,
    ssh_connect_secs: float,
    scp_transfer_secs: float,
    default_remote_cmd_secs: float,
) -> None:
    """Apply harness timeout values to SSH/SCP helpers (call once from ``test.py`` main)."""

    global _SSH_CONNECT_SECS, _SCP_TRANSFER_SECS, _DEFAULT_REMOTE_CMD_SECS
    _SSH_CONNECT_SECS = max(1, int(ssh_connect_secs))
    _SCP_TRANSFER_SECS = max(1, int(scp_transfer_secs))
    _DEFAULT_REMOTE_CMD_SECS = max(1, int(default_remote_cmd_secs))


class DeployError(Exception):
    pass


def _is_transient_ssh_failure(stderr: str, stdout: str = "") -> bool:
    """Return True if ssh/scp output indicates a retryable connection-level failure."""
    combined = f"{stderr}\n{stdout}".lower()
    return (
        "connection timed out" in combined
        or "connection refused" in combined
    )


def _run_ssh_cli_with_retry(
    cmd: list[str],
    host: str,
    *,
    timeout: int | None,
    tool: str = "ssh",
    raise_on_exhausted_transient: bool = True,
) -> subprocess.CompletedProcess:
    """Run ``ssh`` or ``scp`` with retries on transient connection failures.

    Retries at most ``_SSH_MAX_ATTEMPTS`` times with ``_SSH_RETRY_BACKOFF_SEC``
    seconds between attempts. Only ``Connection timed out`` and
    ``Connection refused`` in combined stderr/stdout trigger retries.

    Args:
        cmd: Full argv (including ``ssh`` or ``scp`` as ``cmd[0]``).
        host: Target hostname for logging and error messages.
        timeout: Subprocess timeout, or None for no limit.
        tool: ``\"ssh\"`` or ``\"scp\"`` — used in log lines and :class:`DeployError` text.
        raise_on_exhausted_transient: If False, return the last failed
            :class:`~subprocess.CompletedProcess` when all attempts exhaust on a
            transient error (used by :func:`named_pipe_exists`).

    Returns:
        The completed process (exit code 0 on success).

    Raises:
        DeployError: After all retries are exhausted on a transient failure
            (when ``raise_on_exhausted_transient`` is True), or
            :class:`subprocess.TimeoutExpired` from :func:`subprocess.run`
            (not retried).
    """
    last_result: subprocess.CompletedProcess | None = None
    for attempt in range(1, _SSH_MAX_ATTEMPTS + 1):
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        last_result = result
        if result.returncode == 0:
            return result
        combined = (result.stderr or "") + (result.stdout or "")
        transient = _is_transient_ssh_failure(result.stderr or "", result.stdout or "")
        if transient and attempt < _SSH_MAX_ATTEMPTS:
            log_label = "SSH" if tool == "ssh" else "SCP"
            logger.warning(
                "%s to %s failed (attempt %d/%d), retrying in %ds...",
                log_label,
                host,
                attempt,
                _SSH_MAX_ATTEMPTS,
                _SSH_RETRY_BACKOFF_SEC,
            )
            time.sleep(_SSH_RETRY_BACKOFF_SEC)
            continue
        if transient and attempt == _SSH_MAX_ATTEMPTS:
            if not raise_on_exhausted_transient:
                return result
            exhausted_label = "SSH" if tool == "ssh" else "SCP"
            raise DeployError(
                f"{exhausted_label} to {host} failed after {_SSH_MAX_ATTEMPTS} attempts: "
                f"{combined.strip()}"
            )
        return result
    assert last_result is not None
    return last_result


@dataclass
class TargetConfig:
    host: str
    port: int
    user: str
    work_dir: str
    key: str  # path to SSH private key — required, password auth is not supported
    display: str = ""  # X11 DISPLAY value for Linux targets with Xvfb (e.g. ":99")
    platform: str = "linux"  # "linux" or "windows"

    def __post_init__(self) -> None:
        if self.platform not in ("linux", "windows"):
            raise ValueError(f"platform must be 'linux' or 'windows', got {self.platform!r}")
        if not self.key:
            raise ValueError(
                f"SSH target {self.user}@{self.host}: 'key' is required — "
                "password authentication is not supported (BatchMode=yes is always set). "
                "Generate a key with ssh-keygen and set key= in targets.toml."
            )
        key_path = Path(self.key).expanduser()
        if not key_path.is_file():
            raise ValueError(
                f"SSH target {self.user}@{self.host}: SSH private key file not found: {key_path}"
            )


def _ssh_args(target: TargetConfig) -> list[str]:
    return [
        "ssh",
        "-p", str(target.port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={_SSH_CONNECT_SECS}",
        "-i", target.key,
        f"{target.user}@{target.host}",
    ]


def _scp_args(target: TargetConfig) -> list[str]:
    return [
        "scp",
        "-P", str(target.port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={_SSH_CONNECT_SECS}",
        "-i", target.key,
    ]


def preflight_ssh(target: TargetConfig) -> None:
    """Check that the target host is reachable via SSH before deploying.

    Uses ``ConnectTimeout`` from :func:`configure_deploy_timeouts` so tuning is
    centralised with the rest of the harness.
    Call this at the start of any scenario that deploys a payload via SSH.

    If *target.host* was marked unreachable by :func:`mark_host_unreachable` during
    the startup ``check_ssh_targets()`` pass, raises :class:`~lib.ScenarioSkipped`
    immediately — no SSH attempt is made.  This avoids 3 × ConnectTimeout-second
    retry loops per scenario when the VM is TCP-firewalled (packet drop rather than
    ICMP rejection).

    Raises:
        ScenarioSkipped: if the host is in the globally-unreachable registry.
        DeployError: if the SSH connection cannot be established.
    """
    if target.host in _globally_unreachable_hosts:
        raise ScenarioSkipped(
            f"target {target.host} was unreachable at startup — skipping SSH probe"
        )
    cmd = [
        "ssh",
        "-p", str(target.port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={_SSH_CONNECT_SECS}",
        "-i", target.key,
        f"{target.user}@{target.host}",
        "exit 0",
    ]
    result = _run_ssh_cli_with_retry(
        cmd, target.host, timeout=max(_SSH_CONNECT_SECS + 5, 10), tool="ssh"
    )
    if result.returncode != 0:
        raise DeployError(
            f"target {target.host} not reachable via SSH — "
            "check targets.toml and network"
        )


def preflight_dns(target: TargetConfig, domain: str, expected_ip: str) -> None:
    """Check that ``domain`` resolves to ``expected_ip`` on the target machine.

    On Linux targets, runs a ``python3`` one-liner via SSH.  On Windows targets
    (detected by ``work_dir`` containing backslashes), runs a PowerShell
    ``[System.Net.Dns]::GetHostAddresses()`` probe instead — Windows does not
    ship Python by default and the Microsoft Store stub causes misleading errors.

    DNS listener scenarios (15, 20) require the C2 domain to resolve to the
    teamserver IP on the target's resolver before the agent can check in.
    If the setup is missing the agent silently fails to connect and the scenario
    times out with no indication of the root cause.

    Args:
        target:      SSH target to probe DNS resolution from.
        domain:      C2 domain to resolve (e.g. ``"c2.test.local"``).
        expected_ip: Teamserver IP the domain must map to.

    Raises:
        ScenarioSkipped: if resolution fails or returns an unexpected address,
            with an actionable message describing the required hosts-file
            entry.
    """
    is_windows = target.platform == "windows"
    if is_windows:
        escaped = domain.replace("'", "''")
        probe = (
            "powershell -NoProfile -Command \""
            f"([System.Net.Dns]::GetHostAddresses('{escaped}') "
            "| Where-Object { $_.AddressFamily -eq 'InterNetwork' } "
            "| Select-Object -First 1).IPAddressToString\""
        )
    else:
        probe = (
            "python3 -c 'import socket,sys; print(socket.gethostbyname(sys.argv[1]))' "
            + shlex.quote(domain)
        )
    result = _run_ssh_cli_with_retry(
        _ssh_args(target) + [probe],
        target.host,
        timeout=15,
        tool="ssh",
    )
    hosts_hint = (
        r"C:\Windows\System32\drivers\etc\hosts"
        if is_windows
        else "/etc/hosts"
    )
    if result.returncode != 0:
        raise ScenarioSkipped(
            f"DNS for {domain!r} on {target.host} could not be resolved "
            f"(probe failed: {result.stderr.strip()}); "
            f"add entry to {hosts_hint}: '{expected_ip}  {domain}'"
        )
    actual_ip = result.stdout.strip()
    if actual_ip != expected_ip:
        raise ScenarioSkipped(
            f"DNS for {domain!r} on {target.host} resolves to {actual_ip!r} "
            f"not {expected_ip!r}; "
            f"add entry to {hosts_hint}: '{expected_ip}  {domain}'"
        )


def inject_hosts_entry(target: TargetConfig, domain: str, ip: str) -> None:
    """Ensure the hosts file on *target* maps *domain* to *ip*.

    Idempotent — a no-op if the exact ``"ip  domain"`` line is already
    present.

    On Linux targets, uses ``sudo tee -a`` so the SSH user does not need
    write permission on ``/etc/hosts``; the account must have passwordless
    sudo.

    On Windows targets (detected by ``work_dir`` containing backslashes),
    uses PowerShell to idempotently append to
    ``C:\\Windows\\System32\\drivers\\etc\\hosts``.  The SSH user must have
    Administrator privileges.

    DNS scenarios (15, 20) call this before :func:`preflight_dns` so the
    harness injects the required entry automatically rather than requiring
    manual host configuration on the test VM.

    Args:
        target: SSH target to modify (Linux or Windows).
        domain: Hostname to add (e.g. ``"c2.test.local"``).
        ip:     IP address to map it to (e.g. ``"192.168.213.157"``).

    Raises:
        DeployError: if the SSH command exits non-zero.
    """
    entry = f"{ip}  {domain}"
    is_windows = target.platform == "windows"
    if target.host in _globally_unreachable_hosts:
        return
    if is_windows:
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        escaped_entry = entry.replace("'", "''")
        escaped_path = hosts_path.replace("'", "''")
        cmd = (
            "powershell -NoProfile -Command \""
            f"$h = '{escaped_path}'; "
            f"$e = '{escaped_entry}'; "
            "if (-not (Select-String -Path $h -SimpleMatch $e -Quiet)) "
            "{ Add-Content -Path $h -Value $e }\""
        )
    else:
        cmd = (
            f"grep -qF {shlex.quote(entry)} /etc/hosts || "
            f"echo {shlex.quote(entry)} | sudo tee -a /etc/hosts > /dev/null"
        )
    result = _run_ssh_cli_with_retry(
        _ssh_args(target) + [cmd],
        target.host,
        timeout=15,
        tool="ssh",
    )
    hosts_file = hosts_path if is_windows else "/etc/hosts"
    if result.returncode != 0:
        raise DeployError(
            f"inject_hosts_entry: failed to add '{entry}' to {hosts_file} on "
            f"{target.host} — exit {result.returncode}: {result.stderr.strip()}"
        )
    logger.debug("inject_hosts_entry: '%s' ensured on %s", entry, target.host)


def named_pipe_exists(target: TargetConfig, pipe_name: str, ssh_timeout: int = 25) -> bool:
    """Return True if the named pipe exists on the Windows target (``Test-Path`` on ``\\\\.\\pipe\\``).

    Uses SSH + PowerShell (``Test-Path -LiteralPath``) so the probe runs on the
    same machine the agent will use. Used as a pre-flight after starting an SMB
    listener so bind failures surface before deploy/checkin timeouts.

    Args:
        target:       Windows SSH target.
        pipe_name:    Pipe name suffix (same as listener config, under ``\\\\.\\pipe\\``).
        ssh_timeout:  Per-attempt SSH subprocess timeout in seconds.

    Returns:
        True if PowerShell reports the path exists; False on SSH failure,
        non-zero exit, or stdout other than ``True``.
    """
    if target.host in _globally_unreachable_hosts:
        return False
    safe = pipe_name.replace("'", "''")
    pipe_path = f"\\\\.\\pipe\\{safe}"
    remote_cmd = (
        'powershell -NoProfile -Command '
        f'"Test-Path -LiteralPath \'{pipe_path}\'"'
    )
    result = _run_ssh_cli_with_retry(
        _ssh_args(target) + [remote_cmd],
        target.host,
        timeout=ssh_timeout,
        tool="ssh",
        raise_on_exhausted_transient=False,
    )
    if result.returncode != 0:
        return False
    return result.stdout.strip().lower() == "true"


def run_remote(target: TargetConfig, command: str, timeout: int | None = None) -> str:
    """Run a shell command on the target via SSH and return stdout.

    When *timeout* is ``None``, uses the value set by :func:`configure_deploy_timeouts`
    (default remote command ceiling, typically ``command_output_secs`` from env).
    """
    if timeout is None:
        timeout = _DEFAULT_REMOTE_CMD_SECS
    result = _run_ssh_cli_with_retry(
        _ssh_args(target) + [command],
        target.host,
        timeout=timeout,
        tool="ssh",
    )
    if result.returncode != 0:
        raise DeployError(
            f"Remote command failed (exit {result.returncode}):\n"
            f"  cmd: {command}\n"
            f"  stderr: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def upload(target: TargetConfig, local_path: str | Path, remote_path: str) -> None:
    """SCP a local file to the target."""
    dest = f"{target.user}@{target.host}:{remote_path}"
    result = _run_ssh_cli_with_retry(
        _scp_args(target) + [str(local_path), dest],
        target.host,
        timeout=_SCP_TRANSFER_SECS,
        tool="scp",
    )
    if result.returncode != 0:
        raise DeployError(
            f"SCP upload failed (exit {result.returncode}):\n"
            f"  {local_path} → {dest}\n"
            f"  stderr: {result.stderr.strip()}"
        )


def download(target: TargetConfig, remote_path: str, local_path: str | Path) -> None:
    """SCP a remote file to the local machine."""
    src = f"{target.user}@{target.host}:{remote_path}"
    result = _run_ssh_cli_with_retry(
        _scp_args(target) + [src, str(local_path)],
        target.host,
        timeout=_SCP_TRANSFER_SECS,
        tool="scp",
    )
    if result.returncode != 0:
        raise DeployError(
            f"SCP download failed (exit {result.returncode}):\n"
            f"  {src} → {local_path}\n"
            f"  stderr: {result.stderr.strip()}"
        )


def ensure_work_dir(target: TargetConfig) -> None:
    """Create the work directory on the target if it doesn't exist."""
    if target.platform == "windows":
        run_remote(target, f'powershell -Command "New-Item -ItemType Directory -Force -Path \'{target.work_dir}\'"')
    else:
        run_remote(target, f"mkdir -p {target.work_dir}")


def _quote_posix(path: str) -> str:
    """Shell-quote a path for a POSIX shell (bash/sh)."""
    return shlex.quote(path)


def _quote_powershell(path: str) -> str:
    """Quote a path for PowerShell using single-quote style.

    Single quotes in PowerShell are literal-string delimiters; an embedded
    single quote is escaped by doubling it ('' → ').
    """
    return "'" + path.replace("'", "''") + "'"


def _powershell_encoded_command(script: str) -> str:
    """Return UTF-16 LE Base64 for ``powershell -NoProfile -EncodedCommand``.

    Avoids brittle nested quoting over SSH for multi-statement WMI scripts.
    """

    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _windows_wmi_create_script(command_line: str) -> str:
    """Build PowerShell that runs ``Win32_Process.Create`` and verifies *ReturnValue*.

    Passes the executable's parent directory as *CurrentDirectory* (second argument).
    When that argument is omitted, Windows often starts the child with a poor default
    CWD (for example ``System32``), which breaks Demon/Archon payloads that resolve
    files relative to their install directory.
    """

    exe_path = command_line.strip().strip('"')
    # PureWindowsPath handles backslash separators correctly on Linux.
    parent = str(PureWindowsPath(exe_path).parent)
    if not parent or parent == ".":
        parent = ""

    # CommandLine for Create: quote only when required (spaces in path).
    wmi_cmd = f'"{exe_path}"' if " " in exe_path else exe_path
    arg_cmdline = _quote_powershell(wmi_cmd)
    arg_cwd = _quote_powershell(parent)
    return (
        f"$r = Invoke-WmiMethod -Class Win32_Process -Name Create "
        f"-ArgumentList {arg_cmdline}, {arg_cwd}; "
        "if ($null -eq $r) { throw 'WMI Win32_Process.Create returned null' }; "
        "if ($r.ReturnValue -ne 0) { "
        "throw ('WMI Win32_Process.Create failed: ReturnValue=' + $r.ReturnValue + "
        "' ProcessId=' + $r.ProcessId) "
        "}; "
        "exit 0"
    )


def _windows_schtask_script(exe_path: str, arguments: str = "") -> str:
    """Build PowerShell that uses Task Scheduler to run *exe_path* as the current user.

    Unlike ``WMI Win32_Process.Create`` (which runs as SYSTEM), this approach
    launches the process under the SSH session user's identity.  The task survives
    SSH session close because Task Scheduler is independent of the SSH job object.
    The task registration is removed after launch; the child process keeps running.

    **LogonType strategy**: tries ``Interactive`` first so the task inherits the
    user's existing interactive-session token, which carries full network credentials.
    S4U tokens (the original approach) lack network credentials, causing WinHTTP to
    make no outbound TCP connections even when raw TCP is reachable from PowerShell
    (scenario 17 symptom: process alive, netstat shows zero rows for the C2 port).

    Falls back to ``S4U`` if Interactive registration fails (no interactive session
    available on headless VMs) or if the task stays in ``Queued`` state after 2 s
    (scheduler found no interactive session to bind the task to).

    ``-WorkingDirectory`` is set to the executable's parent folder so payloads do
    not inherit an unexpected CWD such as ``System32``.

    Args:
        exe_path:  Path to the executable (no arguments).
        arguments: Optional arguments string passed via ``-Argument`` to
                   ``New-ScheduledTaskAction``.  Must not include the exe path.
    """
    exe_q = _quote_powershell(exe_path)
    arg_clause = f" -Argument {_quote_powershell(arguments)}" if arguments else ""
    return (
        "$nm = 'RCTest-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 12); "
        f"$ep = {exe_q}; "
        "$wd = Split-Path -Parent -LiteralPath $ep; "
        "if (-not $wd) { $wd = $env:SystemRoot }; "
        "$el = Split-Path -Leaf -LiteralPath $ep; "
        f"$ac = New-ScheduledTaskAction -Execute $ep{arg_clause} -WorkingDirectory $wd; "
        "$st = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable; "
        "$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; "
        # Try Interactive first (full network credentials); fall back to S4U.
        # S4U tokens lack network credentials — WinHTTP makes no TCP connections.
        "$lt = 'S4U'; "
        "try { "
        "  $pr = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Highest -ErrorAction Stop; "
        "  Register-ScheduledTask -TaskName $nm -Action $ac -Settings $st -Principal $pr -Force -ErrorAction Stop | Out-Null; "
        "  $lt = 'Interactive'; "
        "} catch { "
        "  $pr = New-ScheduledTaskPrincipal -UserId $me -LogonType S4U -RunLevel Highest; "
        "  Register-ScheduledTask -TaskName $nm -Action $ac -Settings $st -Principal $pr -Force -ErrorAction Stop | Out-Null; "
        "} "
        "Start-ScheduledTask -TaskName $nm -ErrorAction Stop; "
        # 2 s to settle; Interactive tasks stay Queued when no interactive session exists.
        # When a *different* user is already logged in interactively, Windows returns State='Ready'
        # with LastTaskResult=267011 (0x41303 = SCHED_S_TASK_HAS_NOT_RUN) instead of 'Queued'.
        # Both states signal that the task has not run and the S4U fallback is needed.
        "Start-Sleep -Milliseconds 2000; "
        "$task = Get-ScheduledTask -TaskName $nm -ErrorAction Stop; "
        "$ti_early = Get-ScheduledTaskInfo -TaskName $nm -ErrorAction SilentlyContinue; "
        "$_no_session = ($task.State -eq 'Queued') -or ($task.State -eq 'Ready' -and $ti_early -and [int]$ti_early.LastTaskResult -eq 267011); "
        "if ($lt -eq 'Interactive' -and $_no_session) { "
        "  Unregister-ScheduledTask -TaskName $nm -Confirm:$false -ErrorAction SilentlyContinue; "
        "  $pr = New-ScheduledTaskPrincipal -UserId $me -LogonType S4U -RunLevel Highest; "
        "  Register-ScheduledTask -TaskName $nm -Action $ac -Settings $st -Principal $pr -Force -ErrorAction Stop | Out-Null; "
        "  $lt = 'S4U-fb'; "
        "  Start-ScheduledTask -TaskName $nm -ErrorAction Stop; "
        "  Start-Sleep -Milliseconds 1500; "
        "  $task = Get-ScheduledTask -TaskName $nm -ErrorAction Stop; "
        "} "
        "$ti = Get-ScheduledTaskInfo -TaskName $nm -ErrorAction Stop; "
        "$ss = $task.State; "
        "Write-Output ('RCTEST_SCHTASK_NAME:' + $nm); "
        "Write-Output ('RCTEST_SCHTASK_LOGONTYPE:' + $lt); "
        "Write-Output ('RCTEST_SCHTASK_USER:' + $task.Principal.UserId); "
        "Write-Output ('RCTEST_SCHTASK_LOGON:' + $task.Principal.LogonType); "
        "Write-Output ('RCTEST_SCHTASK_STATE:' + $ss); "
        "Write-Output ('RCTEST_SCHTASK_LASTTASKRESULT:' + $ti.LastTaskResult); "
        "Write-Output ('RCTEST_SCHTASK_LASTRUNTIME:' + $ti.LastRunTime.ToString('o')); "
        # S4U processes have NULL ExecutablePath in WMI; search by name too.
        "$procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ExecutablePath -eq $ep -or ($_.ExecutablePath -eq $null -and $_.Name -eq $el) }; "
        "if ($procs) { "
        "  foreach ($p in $procs) { "
        "    $ow = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue; "
        "    $ot = if ($ow -and $ow.User) { $ow.Domain + '\\\\' + $ow.User } else { '(owner unavailable)' }; "
        "    Write-Output ('RCTEST_SCHTASK_PROCESS:' + $p.ProcessId + '|' + $p.Name + '|' + $ot + '|' + $p.CreationDate); "
        "  } "
        "} else { "
        "  Write-Output ('RCTEST_SCHTASK_PROCESS:(none for ' + $el + ')'); "
        "} "
        "Unregister-ScheduledTask -TaskName $nm -Confirm:$false -ErrorAction SilentlyContinue; "
        "exit 0"
    )


def defender_add_process_exclusion(target: TargetConfig, exe_path: str) -> None:
    """Best-effort Defender process exclusion for the payload *basename* (Windows only).

    ``-ExclusionPath`` on a directory does not always stop real-time inspection
    of a freshly dropped ``.exe``; adding the process name covers H2 gaps where
    the binary is allowed on disk but still blocked at launch.

    Args:
        target:   Windows SSH target.  No-op (raises ``ValueError``) on Linux.
        exe_path: Full remote path; only the final ``.exe`` name is forwarded.
    """
    if target.platform != "windows":
        raise ValueError("defender_add_process_exclusion is only supported on Windows targets")
    if target.host in _globally_unreachable_hosts:
        return
    leaf = PureWindowsPath(exe_path.strip().strip('"')).name
    if not leaf:
        return
    leaf_q = _quote_powershell(leaf)
    script = (
        f"Add-MpPreference -ExclusionProcess {leaf_q} -ErrorAction SilentlyContinue; "
        "exit 0"
    )
    enc = _powershell_encoded_command(script)
    run_remote(target, f"powershell -NoProfile -EncodedCommand {enc}")


def defender_remove_process_exclusion(target: TargetConfig, exe_path: str) -> None:
    """Remove a Defender process exclusion for the payload *basename* (Windows only).

    Symmetric counterpart to :func:`defender_add_process_exclusion`.  Call during
    harness teardown to leave Defender state unchanged after the scenario completes.

    Args:
        target:   Windows SSH target.  Raises ``ValueError`` on Linux targets.
        exe_path: Full remote path; only the final ``.exe`` name is used.
    """
    if target.platform != "windows":
        raise ValueError("defender_remove_process_exclusion is only supported on Windows targets")
    if target.host in _globally_unreachable_hosts:
        return
    leaf = PureWindowsPath(exe_path.strip().strip('"')).name
    if not leaf:
        return
    leaf_q = _quote_powershell(leaf)
    script = (
        f"Remove-MpPreference -ExclusionProcess {leaf_q} -ErrorAction SilentlyContinue; "
        "exit 0"
    )
    enc = _powershell_encoded_command(script)
    run_remote(target, f"powershell -NoProfile -EncodedCommand {enc}")


def firewall_allow_program(target: TargetConfig, program_path: str) -> None:
    """Add a best-effort outbound Windows Firewall allow rule for *program_path*.

    Blocks at the *application* layer (per-exe rules) are a common cause of
    ``Test-NetConnection`` succeeding from PowerShell while an unsigned agent
    binary cannot open TCP (scenario 17 triage).  Failures are swallowed where
    the cmdlet is absent or insufficient privilege (same pattern as Defender).

    Args:
        target:        Windows SSH target.
        program_path:  Full path to the executable on the remote machine.
    """
    if target.platform != "windows":
        raise ValueError("firewall_allow_program is only supported on Windows targets")
    if target.host in _globally_unreachable_hosts:
        return
    digest = hashlib.sha256(program_path.encode("utf-8", errors="replace")).hexdigest()[:12]
    name = f"RC-Harness-{digest}"[:96]
    name_q = _quote_powershell(name)
    prog_q = _quote_powershell(program_path.strip().strip('"'))
    script = (
        f"Remove-NetFirewallRule -DisplayName {name_q} -ErrorAction SilentlyContinue; "
        f"New-NetFirewallRule -DisplayName {name_q} -Direction Outbound -Action Allow "
        f"-Program {prog_q} -ErrorAction SilentlyContinue; "
        "exit 0"
    )
    enc = _powershell_encoded_command(script)
    run_remote(target, f"powershell -NoProfile -EncodedCommand {enc}")


def firewall_remove_program(target: TargetConfig, program_path: str) -> None:
    """Remove the harness outbound Windows Firewall rule for *program_path*.

    Symmetric counterpart to :func:`firewall_allow_program`.  Computes the same
    ``RC-Harness-<digest>`` display name and removes that specific rule.  Call
    during harness teardown to revert the firewall state added for the payload.

    Args:
        target:        Windows SSH target.  Raises ``ValueError`` on Linux targets.
        program_path:  Full path to the executable that was passed to
                       :func:`firewall_allow_program`.
    """
    if target.platform != "windows":
        raise ValueError("firewall_remove_program is only supported on Windows targets")
    if target.host in _globally_unreachable_hosts:
        return
    digest = hashlib.sha256(program_path.encode("utf-8", errors="replace")).hexdigest()[:12]
    name = f"RC-Harness-{digest}"[:96]
    name_q = _quote_powershell(name)
    script = (
        f"Remove-NetFirewallRule -DisplayName {name_q} -ErrorAction SilentlyContinue; "
        "exit 0"
    )
    enc = _powershell_encoded_command(script)
    run_remote(target, f"powershell -NoProfile -EncodedCommand {enc}")


def firewall_allow_outbound_tcp(target: TargetConfig, remote_addr: str, port: int) -> None:
    """Add a best-effort outbound Windows Firewall allow rule for *remote_addr*:*port*.

    Belt-and-suspenders complement to :func:`firewall_allow_program`: that rule
    matches by executable path; this one matches by IP+TCP-port.  Using both
    ensures the traffic is allowed even when the path-based rule does not fire
    (e.g. path normalisation mismatch, rule not yet propagated).

    The rule is named ``RC-Harness-<sha256[:12]>`` so the bulk cleanup
    ``Remove-NetFirewallRule -DisplayName 'RC-Harness-*'`` in
    :func:`cleanup_windows_target` picks it up without extra bookkeeping.

    Args:
        target:      Windows SSH target.
        remote_addr: Destination IP address to allow (C2 callback host).
        port:        Destination TCP port (listener port).
    """
    if target.platform != "windows":
        raise ValueError("firewall_allow_outbound_tcp is only supported on Windows targets")
    if target.host in _globally_unreachable_hosts:
        return
    key = f"outbound-tcp-{remote_addr}-{port}"
    digest = hashlib.sha256(key.encode()).hexdigest()[:12]
    name = f"RC-Harness-{digest}"[:96]
    name_q = _quote_powershell(name)
    addr_q = _quote_powershell(remote_addr.strip())
    script = (
        f"Remove-NetFirewallRule -DisplayName {name_q} -ErrorAction SilentlyContinue; "
        f"New-NetFirewallRule -DisplayName {name_q} -Direction Outbound -Action Allow "
        f"-Protocol TCP -RemoteAddress {addr_q} -RemotePort {port} "
        f"-ErrorAction SilentlyContinue; "
        "exit 0"
    )
    enc = _powershell_encoded_command(script)
    run_remote(target, f"powershell -NoProfile -EncodedCommand {enc}")


def firewall_remove_outbound_tcp(target: TargetConfig, remote_addr: str, port: int) -> None:
    """Remove the harness outbound TCP allow rule for *remote_addr*:*port*.

    Symmetric counterpart to :func:`firewall_allow_outbound_tcp`.  Uses the same
    ``RC-Harness-<digest>`` display name; also handled automatically by the bulk
    sweep in :func:`cleanup_windows_target`.

    Args:
        target:      Windows SSH target.
        remote_addr: Destination IP address (must match what was passed to
                     :func:`firewall_allow_outbound_tcp`).
        port:        Destination TCP port.
    """
    if target.platform != "windows":
        raise ValueError("firewall_remove_outbound_tcp is only supported on Windows targets")
    if target.host in _globally_unreachable_hosts:
        return
    key = f"outbound-tcp-{remote_addr}-{port}"
    digest = hashlib.sha256(key.encode()).hexdigest()[:12]
    name = f"RC-Harness-{digest}"[:96]
    name_q = _quote_powershell(name)
    script = (
        f"Remove-NetFirewallRule -DisplayName {name_q} -ErrorAction SilentlyContinue; "
        "exit 0"
    )
    enc = _powershell_encoded_command(script)
    run_remote(target, f"powershell -NoProfile -EncodedCommand {enc}")


def disable_windows_firewall(target: TargetConfig) -> None:
    """Disable Windows Firewall on all profiles on *target* (Windows only).

    Windows Firewall (mpssvc / FWPM_PROVIDER_MPSSVC_WF) creates FWPM_GENERAL_CONTEXT
    WFP provider context objects that are NOT freed when firewall rules are removed —
    they become zombie objects in kernel non-paged pool.  With ~600 such objects per
    autotest run (each containing ~10 nested items), the total WFP item count reaches
    6000+ after a single run, exhausting non-paged pool and triggering WSAENOBUFS.

    Disabling the firewall on all profiles stops mpssvc from registering any WFP
    filters or creating provider contexts.  The setting persists across reboots.
    This is safe for a dedicated test VM with no internet exposure.

    Also disables Defender Network Protection (EnableNetworkProtection=Disabled) as
    a belt-and-suspenders measure; NP is a separate WFP callout driver that can also
    contribute to pool exhaustion.

    Call once per Windows target during the run preflight.  Idempotent: disabling
    an already-disabled firewall is a no-op in terms of WFP object creation.

    Args:
        target: Windows SSH target.  Raises ``ValueError`` for Linux targets.

    Raises:
        ValueError: when *target* is not a Windows target.
        DeployError: when the SSH connection itself fails.
    """
    if target.platform != "windows":
        raise ValueError("disable_windows_firewall is only supported on Windows targets")

    if target.host in _globally_unreachable_hosts:
        return

    script = (
        "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue; "
        "Set-MpPreference -EnableNetworkProtection Disabled -ErrorAction SilentlyContinue; "
        "exit 0"
    )
    enc = _powershell_encoded_command(script)
    run_remote(target, f"powershell -NoProfile -EncodedCommand {enc}")


def disable_wer(target: TargetConfig) -> None:
    """Disable Windows Error Reporting on *target* to prevent crash dump processing.

    When an agent process crashes (APPCRASH EventID 1000), WER allocates kernel
    non-paged pool for crash dump processing — even before WerFault.exe starts.
    This pool is not released quickly; 10 concurrent agent crashes (sc14 stress)
    can exhaust non-paged pool within seconds, causing subsequent agents to fail
    with WSAENOBUFS (os error 10055) at socket allocation.

    Killing WerFault.exe alone is insufficient because the kernel-mode dump
    collection (drwtsn32 / faultrep / WerKernel) runs before WerFault and has
    already consumed the pool by the time WerFault starts.

    This function disables WER entirely:

    - Sets ``HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\Disabled=1``
      (suppresses all WER processing, user and kernel mode).
    - Sets ``DontShowUI=1`` (suppresses any WER dialog if Disabled is insufficient).
    - Stops the WerSvc service immediately (cleans up any in-flight WER jobs).

    These settings persist across reboots.  Idempotent: calling on an already-
    disabled WER host is a no-op.  Safe for a dedicated test VM.

    Args:
        target: Windows SSH target.

    Raises:
        ValueError: when *target* is not a Windows target.
        DeployError: when the SSH connection itself fails.
    """
    if target.platform != "windows":
        raise ValueError("disable_wer is only supported on Windows targets")

    if target.host in _globally_unreachable_hosts:
        return

    script = (
        "$werKey = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting'\n"
        "Set-ItemProperty -Path $werKey -Name 'Disabled' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue\n"
        "Set-ItemProperty -Path $werKey -Name 'DontShowUI' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue\n"
        "Stop-Service -Name WerSvc -Force -ErrorAction SilentlyContinue\n"
        "exit 0\n"
    )
    enc = _powershell_encoded_command(script)
    run_remote(target, f"powershell -NoProfile -EncodedCommand {enc}")


def defender_add_exclusion(target: TargetConfig, path: str) -> None:
    """Add a Windows Defender AV exclusion for *path* on a Windows target.

    Prevents Defender real-time protection from scanning, quarantining, or
    holding file handles on executables under *path*.  Call this before
    deploying agent payloads to test VMs where Defender is active.

    Errors from ``Add-MpPreference`` are silently suppressed (Defender may be
    disabled or the cmdlet absent on some Windows editions); the function only
    raises ``DeployError`` when the SSH connection itself fails.

    Args:
        target: Windows SSH target.  Raises ``ValueError`` for Linux targets.
        path:   Path to add as an AV exclusion (directory or file).

    Raises:
        ValueError: when *target* is not a Windows target.
        DeployError: when the remote SSH command fails at the transport level.
    """
    if target.platform != "windows":
        raise ValueError("defender_add_exclusion is only supported on Windows targets")
    if target.host in _globally_unreachable_hosts:
        return
    path_q = _quote_powershell(path)
    script = (
        f"Add-MpPreference -ExclusionPath {path_q} -ErrorAction SilentlyContinue; "
        "exit 0"
    )
    enc = _powershell_encoded_command(script)
    run_remote(target, f"powershell -NoProfile -EncodedCommand {enc}")


def windows_sync_payload_probe(
    target: TargetConfig, exe_path: str, *, timeout_ms: int = 8_000
) -> str:
    """Run *exe_path* once under the SSH user; return multiline diagnostic (exit + streams).

    Uses ``System.Diagnostics.Process`` with redirected stdout/stderr. Intended
    for implants that fail fast (exit non-zero before the run loop) so the
    harness can print ``anyhow`` / tracing output from the binary.
    """
    if target.platform != "windows":
        raise ValueError("windows_sync_payload_probe requires a Windows target")
    if target.host in _globally_unreachable_hosts:
        return ""
    exe_q = _quote_powershell(exe_path)
    t = int(timeout_ms)
    script = (
        f"$ep = {exe_q}; "
        "$wd = Split-Path -Parent -LiteralPath $ep; if (-not $wd) { $wd = $env:SystemRoot }; "
        "$psi = New-Object System.Diagnostics.ProcessStartInfo; "
        "$psi.FileName = $ep; $psi.WorkingDirectory = $wd; "
        "$psi.UseShellExecute = $false; "
        "$psi.RedirectStandardError = $true; $psi.RedirectStandardOutput = $true; "
        "$p = New-Object System.Diagnostics.Process; $p.StartInfo = $psi; "
        "[void]$p.Start(); "
        f"$timed_out = -not $p.WaitForExit({t}); "
        "if ($timed_out) { $p.Kill() | Out-Null; Write-Output 'PROBE_TIMEOUT_MS' } "
        "else { Write-Output ('PROBE_EXIT:' + $p.ExitCode) }; "
        "$e = $p.StandardError.ReadToEnd(); "
        "if ($e) { $one = $e.Trim() -replace [Environment]::NewLine, ' | '; Write-Output ('PROBE_STDERR:' + $one) }; "
        "$o = $p.StandardOutput.ReadToEnd(); "
        "if ($o) { $one = $o.Trim() -replace [Environment]::NewLine, ' | '; Write-Output ('PROBE_STDOUT:' + $one) }; "
        "exit 0"
    )
    enc = _powershell_encoded_command(script)
    return run_remote(
        target,
        f"powershell -NoProfile -EncodedCommand {enc}",
        timeout=max(30, t // 1000 + 10),
    )


def execute_background(
    target: TargetConfig,
    command: str,
    arguments: str = "",
    env_vars: dict[str, str] | None = None,
) -> "int | None":
    """Run a command on the target in the background (fire-and-forget).

    On Windows, uses Task Scheduler (``Register-ScheduledTask`` with S4U logon)
    so the child process runs under the SSH session user's identity rather than
    SYSTEM.  The task survives SSH session close because Task Scheduler is
    independent of the SSH job object.  ``Start-Process`` children are killed
    when OpenSSH tears down the session.

    On Linux, the standard ``nohup … &`` detach works because POSIX SSH does
    not use job objects.

    Args:
        target:    SSH target.
        command:   Executable path (Windows) or full command line (Linux).
                   On Windows this must be the executable path only — do not
                   embed arguments here; use *arguments* instead.
        arguments: Optional arguments forwarded via ``-Argument`` to
                   ``New-ScheduledTaskAction`` (Windows only; ignored on Linux).
        env_vars:  Optional environment variables to set before the command
                   (Linux only; ignored on Windows where Task Scheduler
                   inherits the user session environment).  Keys and values
                   are shell-quoted before being prepended to the command.
    """
    if target.platform == "windows":
        # Pass exe and args separately so New-ScheduledTaskAction -Execute receives
        # only the binary path; arguments go via -Argument.
        script = _windows_schtask_script(command, arguments)
        enc = _powershell_encoded_command(script)
        bg_cmd = f"powershell -NoProfile -EncodedCommand {enc}"
    else:
        quoted = _quote_posix(command)
        if env_vars:
            prefix = " ".join(
                f"{shlex.quote(k)}={shlex.quote(v)}" for k, v in env_vars.items()
            )
            bg_cmd = f"{prefix} nohup {quoted} </dev/null >/dev/null 2>&1 &"
        else:
            bg_cmd = f"nohup {quoted} </dev/null >/dev/null 2>&1 &"
    result = _run_ssh_cli_with_retry(
        _ssh_args(target) + [bg_cmd],
        target.host,
        timeout=_SCP_TRANSFER_SECS,
        tool="ssh",
    )
    if result.returncode != 0:
        err_tail = (result.stderr or "").strip()
        out_tail = (result.stdout or "").strip()
        detail_bits = []
        if err_tail:
            detail_bits.append(f"stderr: {err_tail}")
        if out_tail:
            detail_bits.append(f"stdout: {out_tail}")
        detail = "\n  ".join(detail_bits) if detail_bits else "(no output)"
        raise DeployError(
            f"Background remote command failed (exit {result.returncode}):\n"
            f"  {detail}"
        )
    if target.platform == "windows":
        win_out = (result.stdout or "").strip()
        schtask_pid: int | None = None
        if win_out:
            for raw_line in win_out.splitlines():
                line = raw_line.strip()
                if line:
                    print(f"  [deploy][schtask] {line}")
                if line.startswith("RCTEST_SCHTASK_PROCESS:"):
                    val = line[len("RCTEST_SCHTASK_PROCESS:"):]
                    # val is either "PID|Name|Owner|Date" or "(none for <exe>)"
                    if val and not val.startswith("("):
                        try:
                            schtask_pid = int(val.split("|")[0])
                        except ValueError:
                            pass
        return schtask_pid
    return None


def kill_windows_process_by_pid(
    target: TargetConfig,
    pid: int,
    *,
    log_prefix: str = "  [kill-pid]",
) -> None:
    """Kill a process by PID on a Windows target and kill any WerFault.exe.

    Used to reap zombie agent processes that never checked in (no agent ID
    available for ``agent kill``).  Killing WerFault.exe prevents it from
    holding the AMSI lock in Session 0, which would block subsequent agent
    initialisation.

    Never raises: SSH/PowerShell failures are printed and swallowed.

    Args:
        target:     Windows SSH target (no-op on non-Windows or unreachable).
        pid:        PID of the process to terminate.
        log_prefix: Prefix for diagnostic lines printed to the harness log.
    """
    if target.platform != "windows":
        return
    if target.host in _globally_unreachable_hosts:
        return
    script = (
        f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue; "
        "Get-Process -Name WerFault -ErrorAction SilentlyContinue "
        "| Stop-Process -Force -ErrorAction SilentlyContinue; "
        "exit 0"
    )
    enc = _powershell_encoded_command(script)
    try:
        _run_ssh_cli_with_retry(
            _ssh_args(target) + [f"powershell -NoProfile -EncodedCommand {enc}"],
            target.host,
            timeout=30,
            tool="ssh",
        )
        print(f"{log_prefix} killed PID {pid} + WerFault.exe on {target.host}")
    except Exception as exc:
        print(f"{log_prefix} kill PID {pid} failed (non-fatal): {exc}")


def reboot_windows_vm(
    target: TargetConfig,
    *,
    log_prefix: str = "  [wfp-reboot]",
    reboot_timeout: int = 180,
) -> bool:
    """Reboot a Windows VM and wait for SSH to reconnect.

    Issues ``Restart-Computer -Force`` via SSH, waits 20 s for the shutdown to
    begin, then polls for SSH connectivity every 10 s up to *reboot_timeout*
    seconds.

    Use this as a last resort when :func:`wfp_preflight_cleanup` returns
    ``wfp_critical: True`` and mpssvc restart is insufficient — a full reboot
    is the only reliable way to drain WFP zombie objects and recover
    non-paged pool.

    Returns ``True`` if SSH reconnected within the timeout.
    Returns ``False`` if the reboot command failed or SSH did not reconnect.

    Never raises: all SSH failures are printed and swallowed.

    Args:
        target:         Windows SSH target.  No-op (returns False) on Linux.
        log_prefix:     Prefix for diagnostic lines.
        reboot_timeout: Seconds to wait for SSH to reconnect after the reboot
                        command is issued.  Does not include the 20 s pre-poll
                        delay.  Default: 180 s.
    """
    if target.platform != "windows":
        return False
    if target.host in _globally_unreachable_hosts:
        return False

    print(f"{log_prefix} issuing Restart-Computer -Force on {target.host}")
    reboot_enc = _powershell_encoded_command("Restart-Computer -Force\n")
    reboot_cmd = _ssh_args(target) + [
        f"powershell -NoProfile -EncodedCommand {reboot_enc}"
    ]
    reboot_disconnected = False
    try:
        result = _run_ssh_cli_with_retry(reboot_cmd, target.host, timeout=15, tool="ssh")
        if result.returncode != 0:
            if result.returncode == 255:
                print(f"{log_prefix} reboot command lost SSH connection (expected during shutdown)")
                reboot_disconnected = True
            else:
                combined = (result.stderr or "") + (result.stdout or "")
                print(f"{log_prefix} reboot command failed (rc={result.returncode}): {combined.strip()}")
                return False
    except Exception as exc:
        # Log the exception but do NOT set reboot_disconnected here. We have no
        # evidence Restart-Computer ran — the transport could have failed before
        # the command executed. The probe loop will set saw_down when it observes
        # an actual SSH failure, providing real evidence the VM went down.
        print(f"{log_prefix} reboot command raised exception (may or may not indicate shutdown): {exc}")

    print(f"{log_prefix} waiting 20 s for VM shutdown to begin on {target.host}")
    time.sleep(20)

    saw_down = reboot_disconnected
    deadline = time.time() + reboot_timeout
    while time.time() < deadline:
        try:
            probe = subprocess.run(
                _ssh_args(target) + ["echo alive"],
                capture_output=True,
                text=True,
                timeout=8,
            )
            if probe.returncode == 0:
                if saw_down:
                    print(f"{log_prefix} SSH reconnected to {target.host} — VM is back")
                    return True
                print(f"{log_prefix} {target.host} SSH never went down after reboot — no evidence of restart")
                return False
            saw_down = True
        except Exception:
            saw_down = True
        remaining = int(deadline - time.time())
        print(f"{log_prefix} waiting for SSH ({target.host}), ~{remaining}s remaining")
        time.sleep(10)

    print(f"{log_prefix} {target.host} did not respond within {reboot_timeout}s after reboot")
    return False


def wfp_preflight_cleanup(
    target: TargetConfig,
    *,
    log_prefix: str = "  [wfp-preflight]",
    timeout: int | None = None,
    restart_threshold: int | None = None,
    np_pool_threshold: int | None = NP_POOL_BYTES_THRESHOLD,
) -> dict[str, int] | None:
    """Sweep leftover WFP firewall rules and Defender process exclusions.

    Returns a dict with ``wfp_after``, ``twait_after``, ``npb_after``, and optionally
    ``wfp_critical`` parsed from the ``WFP_AFTER:`` diagnostic line, or
    ``None`` if the sweep failed or the target is not Windows.

    When ``restart_threshold`` is set and the post-mpssvc-restart WFP count
    is still >= that threshold, OR when ``np_pool_threshold`` is set and
    non-paged pool bytes are still >= that value, the returned dict includes
    ``wfp_critical: True``.  Callers should treat this as a signal that the
    Windows VM requires a full reboot before further Windows scenarios will
    succeed — mpssvc restart is insufficient to drain these OS-level WFP
    filter objects.

    The mpssvc restart is also triggered when non-paged pool bytes exceed
    ``np_pool_threshold`` even if the WFP item count is below
    ``restart_threshold``.  This catches pool pressure from kernel objects left
    behind by crashed agent processes that do not show up in the WFP item count.

    Idempotent and safe to call multiple times (e.g. at suite start and between
    scenarios); errors are swallowed so a failed sweep never aborts the caller.
    More diagnostic than :func:`cleanup_windows_harness_work_dir`: reports rule counts
    before and after so pool-exhaustion events can be correlated with rule accumulation.

    Removes:
    - All ``RC-Harness-*`` display-name rules (harness-created firewall rules).
    - All ``agent-*`` display-name rules (Windows-auto-created or old-harness-created
      rules from prior agent binaries; accumulate across runs if not swept).
    - ``ExclusionProcess`` entries matching ``agent-*.exe`` / ``stress-agent-*.exe``.

    Never raises: SSH/PowerShell failures are printed and silently swallowed.

    Args:
        target:    Windows SSH target (no-op on Linux targets).
        log_prefix: Prefix for diagnostic lines printed to the harness log.
        timeout:   SSH wait ceiling; defaults to ``max(90, configured remote cmd timeout)``.
        restart_threshold: If ``wfp_after`` is >= this value after the sweep, restart the
                   Windows Firewall service (``mpssvc``) and re-run the sweep once.
                   Rule sweeps cannot remove Defender callout objects; an ``mpssvc``
                   restart is the only reliable way to drain them.  ``None`` disables
                   the threshold check entirely.  Suggested value: 4800.
        np_pool_threshold: If non-paged pool bytes >= this value after the sweep,
                   restart mpssvc regardless of the WFP item count.  ``None`` disables
                   this secondary check.  Default: :data:`NP_POOL_BYTES_THRESHOLD`.
    """
    if target.platform != "windows":
        return None

    if target.host in _globally_unreachable_hosts:
        return None

    if timeout is None:
        timeout = max(90, _DEFAULT_REMOTE_CMD_SECS)

    script = (
        # Kill WerFault.exe first: a crashed Demon/Archon may leave WerFault running in
        # Session 0 holding the AMSI lock, which blocks subsequent agent DllMain init.
        # This must happen before the WFP/pool snapshot so the measurement reflects
        # the post-cleanup state.
        "Get-Process -Name WerFault -ErrorAction SilentlyContinue "
        "| Stop-Process -Force -ErrorAction SilentlyContinue\n"
        # Snapshot rule counts before sweep for diagnostics.
        "$_allrules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue)\n"
        "$_rc_rules = @($_allrules | Where-Object { $_.DisplayName -like 'RC-Harness-*' })\n"
        "$_ag_rules = @($_allrules | Where-Object { $_.DisplayName -like 'agent-*' })\n"
        # Measure raw WFP filter count (covers Defender-owned filters not visible via
        # Get-NetFirewallRule) and TCP TIME_WAIT connections (zombie sockets that consume
        # non-paged pool for up to 4 minutes after close).  Both are leading indicators of
        # pool exhaustion before WSAENOBUFS (os error 10055) occurs.
        "$_wfp_count = -1; $_wfp_tmp = [System.IO.Path]::GetTempFileName()\n"
        "try {\n"
        "  netsh wfp show state \"file=$_wfp_tmp\" 2>$null | Out-Null\n"
        "  $_wfp_count = @(Select-String -LiteralPath $_wfp_tmp -Pattern '<item>' -SimpleMatch -ErrorAction SilentlyContinue).Count\n"
        "} catch {}\n"
        "try { Remove-Item -LiteralPath $_wfp_tmp -Force -ErrorAction SilentlyContinue } catch {}\n"
        "$_twait = @(Get-NetTCPConnection -State TimeWait -ErrorAction SilentlyContinue).Count\n"
        # Measure non-paged pool bytes as the primary pool-pressure indicator.
        # Unlike the WFP item count, this captures pool usage from ALL kernel objects
        # (crashed-process handles, WFP callout objects, etc.) that cause WSAENOBUFS.
        "$_npb = -1\n"
        # Use PerformanceCounter .NET class first (no PerfSvc dependency, no pipeline output
        # that could interfere with Write-Output parsing). Fall back to WMI PerfRawData class
        # which has its own WMI provider and works even when Get-Counter is unavailable.
        "try {\n"
        "  $_pc = [System.Diagnostics.PerformanceCounter]::new('Memory','Pool Nonpaged Bytes')\n"
        "  $_npb = [int64]$_pc.NextValue(); $_pc.Dispose()\n"
        "} catch {}\n"
        "if ($_npb -lt 0) { try {\n"
        "  $_wmi_mem = Get-CimInstance Win32_PerfRawData_PerfOS_Memory -ErrorAction SilentlyContinue\n"
        "  if ($_wmi_mem) { $_npb = [int64]$_wmi_mem.PoolNonpagedBytes }\n"
        "} catch {} }\n"
        "Write-Output ('WFP_BEFORE:rc=' + $_rc_rules.Count + ',agent=' + $_ag_rules.Count + ',wfp=' + $_wfp_count + ',twait=' + $_twait + ',npb=' + $_npb)\n"
        # Remove RC-Harness-* rules (harness-created via firewall_allow_program).
        "Remove-NetFirewallRule -DisplayName 'RC-Harness-*' -ErrorAction SilentlyContinue\n"
        # Remove agent-* display-name rules (Windows-auto-created or old-harness-created).
        "$_ag_rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue\n"
        # Remove ExclusionProcess entries matching agent basename patterns.
        "$_prefs = Get-MpPreference -ErrorAction SilentlyContinue\n"
        "if ($_prefs -and $_prefs.ExclusionProcess) {\n"
        "  foreach ($_exc in @($_prefs.ExclusionProcess)) {\n"
        "    if ($_exc -match '^(agent-|stress-agent-).*\\.exe$') {\n"
        "      Remove-MpPreference -ExclusionProcess $_exc -ErrorAction SilentlyContinue\n"
        "    }\n"
        "  }\n"
        "}\n"
        # Snapshot after sweep.
        "$_allrules_after = @(Get-NetFirewallRule -ErrorAction SilentlyContinue)\n"
        "$_rc_after = @($_allrules_after | Where-Object { $_.DisplayName -like 'RC-Harness-*' }).Count\n"
        "$_ag_after = @($_allrules_after | Where-Object { $_.DisplayName -like 'agent-*' }).Count\n"
        "$_wfp_count_after = -1; $_wfp_tmp2 = [System.IO.Path]::GetTempFileName()\n"
        "try {\n"
        "  netsh wfp show state \"file=$_wfp_tmp2\" 2>$null | Out-Null\n"
        "  $_wfp_count_after = @(Select-String -LiteralPath $_wfp_tmp2 -Pattern '<item>' -SimpleMatch -ErrorAction SilentlyContinue).Count\n"
        "} catch {}\n"
        "try { Remove-Item -LiteralPath $_wfp_tmp2 -Force -ErrorAction SilentlyContinue } catch {}\n"
        "$_twait_after = @(Get-NetTCPConnection -State TimeWait -ErrorAction SilentlyContinue).Count\n"
        "$_npb_after = -1\n"
        "try {\n"
        "  $_pc2 = [System.Diagnostics.PerformanceCounter]::new('Memory','Pool Nonpaged Bytes')\n"
        "  $_npb_after = [int64]$_pc2.NextValue(); $_pc2.Dispose()\n"
        "} catch {}\n"
        "if ($_npb_after -lt 0) { try {\n"
        "  $_wmi_mem2 = Get-CimInstance Win32_PerfRawData_PerfOS_Memory -ErrorAction SilentlyContinue\n"
        "  if ($_wmi_mem2) { $_npb_after = [int64]$_wmi_mem2.PoolNonpagedBytes }\n"
        "} catch {} }\n"
        "Write-Output ('WFP_AFTER:rc=' + $_rc_after + ',agent=' + $_ag_after + ',wfp=' + $_wfp_count_after + ',twait=' + $_twait_after + ',npb=' + $_npb_after)\n"
        "exit 0\n"
    )
    enc = _powershell_encoded_command(script)
    remote = f"powershell -NoProfile -EncodedCommand {enc}"
    cmd = _ssh_args(target) + [remote]
    try:
        result = _run_ssh_cli_with_retry(cmd, target.host, timeout=timeout, tool="ssh")
    except Exception as exc:
        print(f"{log_prefix} skipped ({target.host}): {exc}")
        return None

    if result.returncode != 0:
        err = (result.stderr or "").strip()
        tail = err[-240:] if len(err) > 240 else err
        print(
            f"{log_prefix} remote sweep failed ({target.host}): "
            f"exit {result.returncode} stderr_tail={tail!r}"
        )
        return None

    parsed_after: dict[str, int] | None = None
    for line in (result.stdout or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("WFP_BEFORE:") or stripped.startswith("WFP_AFTER:"):
            label = "before" if stripped.startswith("WFP_BEFORE:") else "after"
            info = stripped.split(":", 1)[1]
            print(f"{log_prefix} rule counts {label} sweep ({target.host}): {info}")
            if stripped.startswith("WFP_AFTER:"):
                try:
                    parts = dict(kv.split("=") for kv in info.split(","))
                    remaining = int(parts.get("rc", 0)) + int(parts.get("agent", 0))
                    if remaining > 0:
                        print(
                            f"{log_prefix} WARNING: {remaining} leftover harness "
                            f"firewall rule(s) still present after sweep on {target.host}"
                        )
                    wfp_after = int(parts.get("wfp", -1))
                    twait_after = int(parts.get("twait", -1))
                    npb_after = int(parts.get("npb", -1))
                    parsed_after = {
                        "wfp_after": wfp_after,
                        "twait_after": twait_after,
                        "npb_after": npb_after,
                    }
                    if npb_after >= 0:
                        npb_mb = npb_after // (1024 * 1024)
                        print(
                            f"{log_prefix} non-paged pool after sweep ({target.host}):"
                            f" {npb_after} bytes ({npb_mb} MB)"
                        )
                except (ValueError, KeyError):
                    pass

    # Determine whether to trigger mpssvc restart.  Two independent conditions:
    # (1) WFP item count >= restart_threshold — WFP filter/context object accumulation.
    # (2) Non-paged pool bytes >= np_pool_threshold — pool pressure from any kernel
    #     objects (crashed process handles, WFP callout objects, etc.).
    wfp_above = (
        restart_threshold is not None
        and parsed_after is not None
        and parsed_after.get("wfp_after", -1) >= restart_threshold
    )
    _npb_val = parsed_after.get("npb_after", -1) if parsed_after is not None else -1
    npb_above = (
        np_pool_threshold is not None
        and parsed_after is not None
        and _npb_val >= 0
        and _npb_val >= np_pool_threshold
    )
    if wfp_above or npb_above:
        # Both conditions above require parsed_after is not None; assert to narrow the type.
        assert parsed_after is not None
        wfp_observed = parsed_after.get("wfp_after", -1)
        npb_observed = parsed_after.get("npb_after", -1)
        reasons = []
        if wfp_above:
            reasons.append(f"wfp_after={wfp_observed} >= threshold={restart_threshold}")
        if npb_above:
            npb_mb = npb_observed // (1024 * 1024)
            reasons.append(
                f"npb_after={npb_observed} ({npb_mb} MB) >= threshold={np_pool_threshold}"
            )
        print(
            f"{log_prefix} WARNING: {'; '.join(reasons)} on {target.host}"
            " — pool pressure detected; restarting mpssvc (Windows Firewall service)."
        )
        restart_script = "Restart-Service -Name mpssvc -Force -ErrorAction Stop\n"
        restart_enc = _powershell_encoded_command(restart_script)
        restart_cmd = _ssh_args(target) + [
            f"powershell -NoProfile -EncodedCommand {restart_enc}"
        ]
        try:
            restart_result = _run_ssh_cli_with_retry(
                restart_cmd, target.host, timeout=timeout, tool="ssh"
            )
        except Exception as exc:
            print(f"{log_prefix} mpssvc restart failed ({target.host}): {exc}")
            # Restart failed — WFP state unchanged; skip the redundant sweep and
            # return the original parsed_after so the caller still has valid data.
            return parsed_after
        if restart_result.returncode != 0:
            err = (restart_result.stderr or "").strip()
            tail = err[-240:] if len(err) > 240 else err
            print(
                f"{log_prefix} WARNING: mpssvc restart failed"
                f" (exit {restart_result.returncode}, {target.host}): {tail!r}"
                " — WFP state unchanged"
            )
            # Restart could not be executed — WFP pool is critically exhausted
            # and cannot self-recover.  Set wfp_critical so callers skip
            # remaining Windows scenarios rather than letting them time out.
            print(
                f"{log_prefix} CRITICAL: mpssvc restart refused by OS on {target.host}"
                f" ({'; '.join(reasons)})"
                " — WFP pool critically exhausted; VM reboot required."
                " Skipping remaining Windows scenarios."
            )
            result_dict = dict(parsed_after)
            result_dict["wfp_critical"] = True
            return result_dict
        print(f"{log_prefix} mpssvc restarted on {target.host}; re-running WFP sweep")
        # Re-run sweep once without thresholds to avoid recursion.
        retry = wfp_preflight_cleanup(
            target,
            log_prefix=log_prefix,
            timeout=timeout,
            restart_threshold=None,
            np_pool_threshold=None,
        )
        if retry is not None:
            retry_wfp = retry.get("wfp_after", -1)
            retry_twait = retry.get("twait_after", -1)
            retry_npb = retry.get("npb_after", -1)
            retry_npb_mb = retry_npb // (1024 * 1024) if retry_npb >= 0 else -1
            print(
                f"{log_prefix} post-mpssvc-restart wfp_after={retry_wfp}"
                f" twait_after={retry_twait}"
                f" npb_after={retry_npb} ({retry_npb_mb} MB)"
            )
            still_wfp = restart_threshold is not None and retry_wfp >= restart_threshold
            still_npb = (
                np_pool_threshold is not None
                and retry_npb >= 0
                and retry_npb >= np_pool_threshold
            )
            if still_wfp or still_npb:
                # mpssvc restart did not reduce pool pressure — these are accumulated
                # OS-level kernel objects that only clear on full VM reboot.
                post_reasons = []
                if still_wfp:
                    post_reasons.append(
                        f"wfp_after={retry_wfp} >= threshold={restart_threshold}"
                    )
                if still_npb:
                    post_reasons.append(
                        f"npb_after={retry_npb} ({retry_npb_mb} MB)"
                        f" >= threshold={np_pool_threshold}"
                    )
                print(
                    f"{log_prefix} CRITICAL: post-mpssvc-restart {'; '.join(post_reasons)}"
                    f" on {target.host}"
                    " — WFP pool critically exhausted; VM reboot required."
                    " Skipping remaining Windows scenarios."
                )
                retry["wfp_critical"] = True
        # Fall back to the pre-restart data if the retry sweep returned nothing
        # (e.g. SSH re-sweep timed out or WFP_AFTER output was missing).
        return retry if retry is not None else parsed_after

    return parsed_after


def cleanup_windows_harness_work_dir(
    target: TargetConfig,
    *,
    log_prefix: str = "  [win-workdir]",
    timeout: int | None = None,
) -> None:
    """Stop processes running from *target.work_dir*, then delete harness-owned files.

    Removes only well-known autotest artifacts: ``agent-*.exe``, ``stress-agent-*.exe``,
    and ``uploaded-*.dat`` under the Windows work directory. This avoids the noisy
    ``Access to the path ... is denied`` failures from ``Remove-Item -Recurse`` when
    stale payload binaries are still loaded or scanning-locked.

    Also reverts per-run Defender/firewall exceptions added by
    :func:`defender_add_process_exclusion` and :func:`firewall_allow_program`:

    - Removes all Windows Firewall rules whose display name starts with ``RC-Harness-``
      (the stable prefix used by :func:`firewall_allow_program`).
    - Removes all ``ExclusionProcess`` entries matching ``agent-*.exe`` or
      ``stress-agent-*.exe`` (the basename patterns used by harness payloads).

    This sweep always executes before the work-dir file removal so it runs even when
    the work directory does not yet exist (e.g. pre-run cleanup on a fresh VM).

    Never raises: SSH failures, non-zero exit, or locked files are summarized on stdout.

    Args:
        target: Windows SSH target (no-op when ``work_dir`` is a POSIX path).
        log_prefix: Prefix for diagnostic lines printed to the harness log.
        timeout: SSH wait ceiling; defaults to ``max(90, configured remote cmd timeout)``.
    """

    is_windows = target.platform == "windows"
    if not is_windows:
        return

    if target.host in _globally_unreachable_hosts:
        return

    if timeout is None:
        timeout = max(90, _DEFAULT_REMOTE_CMD_SECS)

    wd = target.work_dir.replace("'", "''")
    script = (
        # Revert Defender/firewall exceptions — runs unconditionally (even without work dir).
        # RC-Harness-* rules: added by firewall_allow_program / firewall_allow_outbound_tcp.
        "Remove-NetFirewallRule -DisplayName 'RC-Harness-*' -ErrorAction SilentlyContinue\n"
        # agent-* rules: Windows may auto-create rules using the exe basename as DisplayName.
        "Get-NetFirewallRule -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName -like 'agent-*' } | "
        "Remove-NetFirewallRule -ErrorAction SilentlyContinue\n"
        "$_prefs = Get-MpPreference -ErrorAction SilentlyContinue\n"
        "if ($_prefs -and $_prefs.ExclusionProcess) {\n"
        "  foreach ($_exc in @($_prefs.ExclusionProcess)) {\n"
        "    if ($_exc -match '^(agent-|stress-agent-).*\\.exe$') {\n"
        "      Remove-MpPreference -ExclusionProcess $_exc -ErrorAction SilentlyContinue\n"
        "    }\n"
        "  }\n"
        "}\n"
        # Kill WerFault.exe before stopping agent processes.  When a Demon agent crashes on
        # TerminateProcess (APPCRASH EventID 1000), WerFault.exe holds the agent binary open
        # for crash-dump processing and consumes non-paged pool.  Subsequent agents fail with
        # WSAENOBUFS (os error 10055) when that pool is exhausted.  On a test VM every
        # WerFault instance is processing an agent crash — kill it unconditionally.
        "Get-Process -Name WerFault -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue\n"
        # Work-dir file cleanup.
        + f"$wd = '{wd}'\n"
        "if (-not (Test-Path -LiteralPath $wd)) { exit 0 }\n"
        "Get-Process -ErrorAction SilentlyContinue | ForEach-Object {\n"
        "  $proc = $_\n"
        "  try {\n"
        "    if ($proc.Path -and ($proc.Path.StartsWith($wd, "
        "[StringComparison]::OrdinalIgnoreCase))) {\n"
        "      Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue\n"
        "    }\n"
        "  } catch { }\n"
        "}\n"
        "Start-Sleep -Milliseconds 1500\n"
        # Retry loop: WER crash-dump processing holds agent-*.exe files for up to ~30 s.
        # Kill WerFault.exe between retries to accelerate pool release.
        "$locked = New-Object System.Collections.Generic.List[string]\n"
        "$maxRetries = 10\n"
        "for ($retry = 0; $retry -lt $maxRetries; $retry++) {\n"
        "  $locked.Clear()\n"
        "  foreach ($pat in @('agent-*.exe','stress-agent-*.exe','uploaded-*.dat')) {\n"
        "    Get-ChildItem -LiteralPath $wd -Filter $pat -ErrorAction SilentlyContinue "
        "| ForEach-Object {\n"
        "      $f = $_\n"
        "      try {\n"
        "        Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop\n"
        "      } catch {\n"
        "        $locked.Add($f.FullName) | Out-Null\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "  if ($locked.Count -eq 0) { break }\n"
        "  Get-Process -Name WerFault -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue\n"
        "  if ($retry -lt ($maxRetries - 1)) { Start-Sleep -Seconds 3 }\n"
        "}\n"
        "if ($locked.Count -gt 0) {\n"
        "  Write-Output ('HARNESS_LOCKED_FILES:' + ($locked -join ';'))\n"
        "}\n"
        "exit 0\n"
    )
    enc = _powershell_encoded_command(script)
    remote = f"powershell -NoProfile -EncodedCommand {enc}"
    cmd = _ssh_args(target) + [remote]
    try:
        result = _run_ssh_cli_with_retry(
            cmd,
            target.host,
            timeout=timeout,
            tool="ssh",
        )
    except Exception as exc:
        print(f"{log_prefix} cleanup skipped ({target.host}): {exc}")
        return

    if result.returncode != 0:
        err = (result.stderr or "").strip()
        tail = err[-240:] if len(err) > 240 else err
        print(
            f"{log_prefix} remote cleanup failed ({target.host}): "
            f"exit {result.returncode} stderr_tail={tail!r}"
        )
        return

    for line in (result.stdout or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("HARNESS_LOCKED_FILES:"):
            payload = stripped.split(":", 1)[1].strip()
            print(
                f"{log_prefix} locked harness files remain ({target.host}): {payload}"
            )
            return
