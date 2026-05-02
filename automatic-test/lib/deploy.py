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

    Raises:
        DeployError: if the SSH connection cannot be established.
    """
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
        "$name = 'RCTest-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 12); "
        f"$exePath = {exe_q}; "
        "$workDir = Split-Path -Parent -LiteralPath $exePath; "
        "if (-not $workDir) { $workDir = $env:SystemRoot }; "
        "$exeLeaf = Split-Path -Leaf -LiteralPath $exePath; "
        f"$action = New-ScheduledTaskAction -Execute $exePath{arg_clause} "
        "-WorkingDirectory $workDir; "
        "$settings = New-ScheduledTaskSettingsSet "
        "-ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable; "
        "$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; "
        # Try Interactive first (preserves network credentials); fall back to S4U.
        "$usedLogonType = 'S4U'; "
        "try { "
        "  $principal = New-ScheduledTaskPrincipal -UserId $me "
        "    -LogonType Interactive -RunLevel Highest -ErrorAction Stop; "
        "  Register-ScheduledTask -TaskName $name -Action $action "
        "    -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null; "
        "  $usedLogonType = 'Interactive'; "
        "  Write-Output 'RCTEST_SCHTASK_LOGONTYPE:Interactive(attempt)'; "
        "} catch { "
        "  $usedLogonType = 'S4U'; "
        "  Write-Output ('RCTEST_SCHTASK_LOGONTYPE_WARN:Interactive failed: ' + $_.Exception.Message.Split([Environment]::NewLine)[0]); "
        "  $principal = New-ScheduledTaskPrincipal -UserId $me -LogonType S4U -RunLevel Highest; "
        "  Register-ScheduledTask -TaskName $name -Action $action "
        "    -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null; "
        "  Write-Output 'RCTEST_SCHTASK_LOGONTYPE:S4U'; "
        "} "
        "Start-ScheduledTask -TaskName $name -ErrorAction Stop; "
        # Wait 2 s for the state to settle; Interactive tasks stay Queued when no
        # interactive session exists, which is the cue to re-register with S4U.
        "Start-Sleep -Milliseconds 2000; "
        "$task = Get-ScheduledTask -TaskName $name -ErrorAction Stop; "
        "if ($usedLogonType -eq 'Interactive' -and $task.State -eq 'Queued') { "
        "  Write-Output 'RCTEST_SCHTASK_LOGONTYPE_WARN:Interactive Queued (no session) — retrying as S4U'; "
        "  Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue; "
        "  $principal = New-ScheduledTaskPrincipal -UserId $me -LogonType S4U -RunLevel Highest; "
        "  Register-ScheduledTask -TaskName $name -Action $action "
        "    -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null; "
        "  Write-Output 'RCTEST_SCHTASK_LOGONTYPE:S4U(queued-fallback)'; "
        "  $usedLogonType = 'S4U'; "
        "  Start-ScheduledTask -TaskName $name -ErrorAction Stop; "
        "  Start-Sleep -Milliseconds 1500; "
        "  $task = Get-ScheduledTask -TaskName $name -ErrorAction Stop; "
        "} "
        "$ti = Get-ScheduledTaskInfo -TaskName $name -ErrorAction Stop; "
        "$st = $task.State; "
        "Write-Output ('RCTEST_SCHTASK_NAME:' + $name); "
        "Write-Output ('RCTEST_SCHTASK_USER:' + $task.Principal.UserId); "
        "Write-Output ('RCTEST_SCHTASK_LOGON:' + $task.Principal.LogonType); "
        "Write-Output ('RCTEST_SCHTASK_STATE:' + $st); "
        "Write-Output ('RCTEST_SCHTASK_LASTTASKRESULT:' + $ti.LastTaskResult); "
        "Write-Output ('RCTEST_SCHTASK_LASTRUNTIME:' + $ti.LastRunTime.ToString('o')); "
        # Process probe: S4U processes have NULL ExecutablePath in WMI; search by name too.
        "$procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ExecutablePath -eq $exePath -or ($_.ExecutablePath -eq $null -and $_.Name -eq $exeLeaf) }; "
        "if ($procs) { "
        "  foreach ($p in $procs) { "
        "    $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue; "
        "    $ownerText = if ($owner -and $owner.User) { $owner.Domain + '\\\\' + $owner.User } else { '(owner unavailable)' }; "
        "    Write-Output ('RCTEST_SCHTASK_PROCESS:' + $p.ProcessId + '|' + $p.Name + '|' + $ownerText + '|' + $p.CreationDate); "
        "  } "
        "} else { "
        "  Write-Output ('RCTEST_SCHTASK_PROCESS:(none for ' + $exeLeaf + ')'); "
        "} "
        "Unregister-ScheduledTask -TaskName $name -Confirm:$false "
        "-ErrorAction SilentlyContinue; "
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


def defender_network_protection_exclusion(target: TargetConfig, ip_address: str) -> None:
    """Add a Defender Network Protection IP exclusion for *ip_address* (Windows only).

    Windows Defender Network Protection (SmartScreen network enforcement) can
    silently drop WinHTTP outbound connections from untrusted executables running
    under S4U Task Scheduler sessions, even when raw TCP to the same host succeeds
    from PowerShell.  The symptom is: agent alive, netstat shows zero rows for the
    C2 port (no SYN generated — WinHTTP gets an immediate internal block error).

    ``Add-MpPreference -ExclusionIpAddress`` tells Network Protection to allow
    connections to/from the specified IP, bypassing reputation-based blocking.
    Errors are silently swallowed (Defender may be absent or already disabled).

    Args:
        target:     Windows SSH target.  Raises ``ValueError`` for Linux targets.
        ip_address: C2 callback host IP to exclude from network inspection.

    Raises:
        ValueError: when *target* is not a Windows target.
        DeployError: when the SSH connection itself fails.
    """
    if target.platform != "windows":
        raise ValueError(
            "defender_network_protection_exclusion is only supported on Windows targets"
        )
    ip_q = _quote_powershell(ip_address.strip())
    script = (
        f"Add-MpPreference -ExclusionIpAddress {ip_q} -ErrorAction SilentlyContinue; "
        "exit 0"
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
    path_q = _quote_powershell(path)
    script = (
        f"Add-MpPreference -ExclusionPath {path_q} -ErrorAction SilentlyContinue; "
        "exit 0"
    )
    enc = _powershell_encoded_command(script)
    run_remote(target, f"powershell -NoProfile -EncodedCommand {enc}")


def execute_background(target: TargetConfig, command: str, arguments: str = "") -> None:
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
    """
    if target.platform == "windows":
        # Pass exe and args separately so New-ScheduledTaskAction -Execute receives
        # only the binary path; arguments go via -Argument.
        script = _windows_schtask_script(command, arguments)
        enc = _powershell_encoded_command(script)
        bg_cmd = f"powershell -NoProfile -EncodedCommand {enc}"
    else:
        quoted = _quote_posix(command)
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
        if win_out:
            for raw_line in win_out.splitlines():
                line = raw_line.strip()
                if line:
                    print(f"  [deploy][schtask] {line}")


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

    Never raises: SSH failures, non-zero exit, or locked files are summarized on stdout.

    Args:
        target: Windows SSH target (no-op when ``work_dir`` is a POSIX path).
        log_prefix: Prefix for diagnostic lines printed to the harness log.
        timeout: SSH wait ceiling; defaults to ``max(90, configured remote cmd timeout)``.
    """

    is_windows = target.platform == "windows"
    if not is_windows:
        return

    if timeout is None:
        timeout = max(90, _DEFAULT_REMOTE_CMD_SECS)

    wd = target.work_dir.replace("'", "''")
    script = (
        f"$wd = '{wd}'\n"
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
        "Start-Sleep -Milliseconds 800\n"
        "$locked = New-Object System.Collections.Generic.List[string]\n"
        "foreach ($pat in @('agent-*.exe','stress-agent-*.exe','uploaded-*.dat')) {\n"
        "  Get-ChildItem -LiteralPath $wd -Filter $pat -ErrorAction SilentlyContinue "
        "| ForEach-Object {\n"
        "    $f = $_\n"
        "    try {\n"
        "      Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop\n"
        "    } catch {\n"
        "      $locked.Add($f.FullName) | Out-Null\n"
        "    }\n"
        "  }\n"
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
