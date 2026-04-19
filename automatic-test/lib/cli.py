"""
lib/cli.py — thin subprocess wrapper around red-cell-cli.

Every public function returns a dict parsed from the CLI's JSON stdout.
On failure (non-zero exit or {"ok": false, ...}) a CliError is raised.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any


class CliError(Exception):
    def __init__(self, code: str, message: str, exit_code: int):
        super().__init__(f"[{code}] {message} (exit {exit_code})")
        self.code = code
        self.message = message
        self.exit_code = exit_code


class AgentNotSupportedError(Exception):
    """Raised when a payload build is requested for an agent type that is not
    yet supported by the current CLI / teamserver build.

    The CLI ``--agent`` flag is not yet implemented; until it is, only
    ``"demon"`` can be built.  See red-cell-c2-iyl94.
    """

    def __init__(self, agent: str) -> None:
        super().__init__(
            f"payload build for agent {agent!r} is not yet supported — "
            f"CLI --agent flag not implemented (see red-cell-c2-iyl94)"
        )
        self.agent = agent


@dataclass
class CliConfig:
    server: str
    token: str
    binary: str = "red-cell-cli"
    timeout: int = 30
    #: Hard ceiling on subprocess wall-clock time (seconds).  The per-invocation
    #: timeout is ``min(timeout + 10, max_subprocess_secs)``.
    max_subprocess_secs: int = 120
    extra_env: dict[str, str] = field(default_factory=dict)
    cert_fingerprint: str | None = None

    def with_token(self, token: str) -> "CliConfig":
        """Return a copy of this config with a different token, preserving all other fields."""
        from dataclasses import replace
        return replace(self, token=token)

    def with_timeout(self, timeout: int) -> "CliConfig":
        """Return a copy of this config with a longer timeout, also extending max_subprocess_secs
        so the subprocess is not killed before the timeout expires."""
        from dataclasses import replace
        return replace(self, timeout=timeout, max_subprocess_secs=max(timeout + 10, self.max_subprocess_secs))


def _run(cfg: CliConfig, *args: str) -> dict[str, Any]:
    env = os.environ.copy()
    env["RC_SERVER"] = cfg.server
    env["RC_TOKEN"] = cfg.token
    env.update(cfg.extra_env)

    # The CLI's --timeout flag controls how long the binary waits for a server
    # response.  We add a 10-second buffer so the subprocess is killed only
    # after the CLI has had a chance to time out gracefully.  The result is
    # capped by max_subprocess_secs so runaway --timeout values can't block
    # the test suite indefinitely.
    subprocess_timeout = min(cfg.timeout + 10, cfg.max_subprocess_secs)

    try:
        fp_args = ["--cert-fingerprint", cfg.cert_fingerprint] if cfg.cert_fingerprint else []
        result = subprocess.run(
            [cfg.binary, "--output", "json", "--timeout", str(cfg.timeout), *fp_args, *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=subprocess_timeout,
        )
    except subprocess.TimeoutExpired:
        raise CliError(
            "SUBPROCESS_TIMEOUT",
            f"CLI subprocess did not exit within expected timeout ({subprocess_timeout}s)",
            -1,
        )
    except FileNotFoundError:
        raise CliError(
            "BINARY_NOT_FOUND",
            f"CLI binary not found: {cfg.binary!r} — is it installed and on PATH?",
            127,
        )

    stdout = result.stdout.strip()
    if stdout:
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            raise CliError("PARSE_ERROR", f"non-JSON stdout: {stdout!r}", result.returncode)
    else:
        data = {}

    if result.returncode != 0 or not data.get("ok", True):
        # Try to parse stderr as a structured error envelope so that machine-
        # readable error codes survive even when stdout is empty or bare text.
        stderr_data: dict[str, Any] = {}
        stderr_raw = result.stderr.strip()
        if stderr_raw:
            try:
                parsed = json.loads(stderr_raw)
                if isinstance(parsed, dict):
                    stderr_data = parsed
            except json.JSONDecodeError:
                pass

        error = data.get("error") or stderr_data.get("error") or "UNKNOWN"
        msg = (
            data.get("message")
            or stderr_data.get("message")
            or stderr_raw
            or "no message"
        )
        raise CliError(error, msg, result.returncode)

    return data.get("data", data)


# ── Auth ────────────────────────────────────────────────────────────────────

def login(cfg: CliConfig) -> str:
    """Verify the configured API key and return it.

    The REST API uses static API keys — there is no username/password login
    endpoint.  This helper validates the key by performing an authenticated
    status request and returns the key unchanged on success.  A CliError with
    exit_code 3 is raised if the key is rejected.
    """
    status(cfg)  # raises CliError (exit 3) if the key is invalid
    return cfg.token


def status(cfg: CliConfig) -> dict[str, Any]:
    return _run(cfg, "status")


# ── Listeners ───────────────────────────────────────────────────────────────

def listener_list(cfg: CliConfig) -> list[dict]:
    return _run(cfg, "listener", "list")


def listener_create(cfg: CliConfig, name: str, type_: str, **kwargs) -> dict:
    extra = []
    for k, v in kwargs.items():
        flag = f"--{k.replace('_', '-')}"
        if isinstance(v, bool):
            if v:
                extra.append(flag)
        else:
            extra += [flag, str(v)]
    return _run(cfg, "listener", "create", "--name", name, "--type", type_, *extra)


def listener_start(cfg: CliConfig, name: str) -> dict:
    return _run(cfg, "listener", "start", name)


def listener_stop(cfg: CliConfig, name: str) -> dict:
    return _run(cfg, "listener", "stop", name)


def listener_delete(cfg: CliConfig, name: str) -> dict:
    return _run(cfg, "listener", "delete", name)


# ── Payloads ────────────────────────────────────────────────────────────────

def payload_build(cfg: CliConfig, listener: str,
                  arch: str = "x64", fmt: str = "exe",
                  agent: str = "demon",
                  sleep_secs: int | None = None,
                  wait: bool = False) -> dict:
    """Submit a payload build job.

    Without ``wait``: returns ``{"job_id": ...}`` immediately.
    With ``wait=True``: blocks until build completes via the CLI's
    ``--wait`` flag, returns ``{"id": <payload_id>, "size_bytes": N}``.

    """
    args = ["payload", "build",
            "--listener", listener,
            "--arch", arch,
            "--format", fmt,
            "--agent", agent]
    if sleep_secs is not None:
        args += ["--sleep", str(sleep_secs)]
    if wait:
        args.append("--wait")
        # Payload compilation can take several minutes; extend the subprocess
        # lifetime to match the CLI's built-in --wait-timeout default (300s).
        run_cfg = cfg.with_timeout(300)
    else:
        run_cfg = cfg
    return _run(run_cfg, *args)


def payload_cache_flush(cfg: CliConfig) -> dict:
    """Flush all cached payload build artifacts.  Admin-only endpoint."""
    return _run(cfg, "payload", "cache-flush")


def payload_download(cfg: CliConfig, payload_id: str | int, dst: str) -> dict:
    """Download a built payload to a local file."""
    return _run(cfg, "payload", "download", str(payload_id), "--dst", dst)


def payload_build_and_fetch(cfg: CliConfig, listener: str,
                            arch: str = "x64", fmt: str = "exe",
                            agent: str = "demon",
                            sleep_secs: int | None = None) -> bytes:
    """Build a payload (blocking) and return the raw bytes.

    Combines ``payload build --wait`` with ``payload download`` into a
    single call.  A temporary file is used to receive the download and
    is deleted before returning.

    """
    result = payload_build(cfg, listener=listener, arch=arch, fmt=fmt,
                           agent=agent, sleep_secs=sleep_secs, wait=True)
    payload_id = result["id"]

    fd, tmp_path = tempfile.mkstemp(suffix=f".{fmt}")
    os.close(fd)
    try:
        payload_download(cfg, payload_id, tmp_path)
        with open(tmp_path, "rb") as fh:
            return fh.read()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ── Agents ──────────────────────────────────────────────────────────────────

def agent_list(cfg: CliConfig) -> list[dict]:
    return _run(cfg, "agent", "list")


def agent_show(cfg: CliConfig, agent_id: str) -> dict:
    return _run(cfg, "agent", "show", agent_id)


def wait_for_agent_id(
    cfg: CliConfig,
    agent_id_hex: str,
    timeout: float = 10.0,
    interval: float = 0.5,
) -> dict:
    """Poll ``agent list`` until the agent with ``agent_id_hex`` appears.

    Returns the result of ``agent show`` for that agent.
    Raises ``TimeoutError`` if the agent does not appear within ``timeout`` seconds.

    ``agent_id_hex`` is matched case-insensitively so callers can pass either
    upper- or lower-case hex strings.
    """
    import time as _time

    needle = agent_id_hex.upper()
    deadline = _time.monotonic() + timeout
    while _time.monotonic() < deadline:
        try:
            agents = agent_list(cfg)
            for entry in agents:
                if str(entry.get("id", "")).upper() == needle:
                    return agent_show(cfg, agent_id_hex)
        except CliError:
            pass
        _time.sleep(interval)
    raise TimeoutError(
        f"Agent {agent_id_hex} did not appear in agent list within {timeout:.0f}s"
    )


def agent_exec(cfg: CliConfig, agent_id: str, cmd: str,
               wait: bool = True, timeout: int | None = None) -> dict:
    args = ["agent", "exec", agent_id, "--cmd", cmd]
    if wait:
        args.append("--wait")
    if timeout is not None:
        args += ["--wait-timeout", str(timeout)]
    return _run(cfg, *args)


def agent_upload(cfg: CliConfig, agent_id: str, src: str, dst: str) -> dict:
    return _run(cfg, "agent", "upload", agent_id, "--src", src, "--dst", dst)


def agent_download(cfg: CliConfig, agent_id: str, src: str, dst: str) -> dict:
    return _run(cfg, "agent", "download", agent_id, "--src", src, "--dst", dst)


def agent_kill(cfg: CliConfig, agent_id: str) -> dict:
    return _run(cfg, "agent", "kill", agent_id, "--wait")


def agent_output(
    cfg: CliConfig,
    agent_id: str,
    since: int | None = None,
) -> list[dict]:
    """Fetch persisted agent output (``agent output`` — not ``--watch``)."""
    args = ["agent", "output", agent_id]
    if since is not None:
        args += ["--since", str(since)]
    return _run(cfg, *args)


# ── Operators ────────────────────────────────────────────────────────────────

def operator_list(cfg: CliConfig) -> list[dict]:
    return _run(cfg, "operator", "list")


def operator_create(cfg: CliConfig, username: str, password: str, role: str) -> dict:
    return _run(cfg, "operator", "create", username,
                "--password", password, "--role", role)


def operator_delete(cfg: CliConfig, username: str) -> dict:
    return _run(cfg, "operator", "delete", username)


def operator_set_role(cfg: CliConfig, username: str, role: str) -> dict:
    """Change an operator's role via ``operator set-role``."""
    return _run(cfg, "operator", "set-role", username, role)


# ── Loot ─────────────────────────────────────────────────────────────────────

def loot_list(
    cfg: CliConfig,
    kind: str | None = None,
    agent_id: str | None = None,
    operator: str | None = None,
    since: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    """Return the loot list, optionally filtered by kind, agent, operator, or time."""
    args = ["loot", "list"]
    if kind:
        args += ["--kind", kind]
    if agent_id:
        args += ["--agent", agent_id]
    if operator:
        args += ["--operator", operator]
    if since:
        args += ["--since", since]
    if limit is not None:
        args += ["--limit", str(limit)]
    return _run(cfg, *args)


def loot_download(cfg: CliConfig, loot_id: int, dst: str) -> dict:
    """Download raw loot bytes to a local file.  Returns the result dict."""
    return _run(cfg, "loot", "download", str(loot_id), "--out", dst)


# ── Audit log ─────────────────────────────────────────────────────────────────

def log_list(
    cfg: CliConfig,
    operator: str | None = None,
    action: str | None = None,
    agent_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    """Return audit log entries (newest first), optionally filtered.

    Each entry has keys: ts, operator, action, agent_id, detail, result_status.
    """
    args = ["log", "list"]
    if operator:
        args += ["--operator", operator]
    if action:
        args += ["--action", action]
    if agent_id:
        args += ["--agent", agent_id]
    if since:
        args += ["--since", since]
    if until:
        args += ["--until", until]
    if limit is not None:
        args += ["--limit", str(limit)]
    return _run(cfg, *args)
