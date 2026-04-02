"""
lib/cli.py — thin subprocess wrapper around red-cell-cli.

Every public function returns a dict parsed from the CLI's JSON stdout.
On failure (non-zero exit or {"ok": false, ...}) a CliError is raised.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any


class CliError(Exception):
    def __init__(self, code: str, message: str, exit_code: int):
        super().__init__(f"[{code}] {message} (exit {exit_code})")
        self.code = code
        self.message = message
        self.exit_code = exit_code


@dataclass
class CliConfig:
    server: str
    token: str
    binary: str = "red-cell-cli"
    timeout: int = 30
    extra_env: dict[str, str] = field(default_factory=dict)


def _run(cfg: CliConfig, *args: str) -> dict[str, Any]:
    env = os.environ.copy()
    env["RC_SERVER"] = cfg.server
    env["RC_TOKEN"] = cfg.token
    env.update(cfg.extra_env)

    try:
        result = subprocess.run(
            [cfg.binary, "--output", "json", "--timeout", str(cfg.timeout), *args],
            capture_output=True,
            text=True,
            env=env,
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
        error = data.get("error", "UNKNOWN")
        msg = data.get("message", result.stderr.strip() or "no message")
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
        extra += [f"--{k.replace('_', '-')}", str(v)]
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
                  sleep_secs: int | None = None,
                  wait: bool = False) -> dict:
    """Submit a payload build job.

    Without ``wait``: returns ``{"job_id": ...}`` immediately.
    With ``wait=True``: polls until build completes, returns
    ``{"id": <payload_id>, "size_bytes": N}``.
    """
    args = ["payload", "build",
            "--listener", listener,
            "--arch", arch,
            "--format", fmt]
    if sleep_secs is not None:
        args += ["--sleep", str(sleep_secs)]
    if wait:
        args.append("--wait")
    return _run(cfg, *args)


def payload_download(cfg: CliConfig, payload_id: str | int, dst: str) -> dict:
    """Download a built payload to a local file."""
    return _run(cfg, "payload", "download", str(payload_id), "--dst", dst)


def payload_build_and_fetch(cfg: CliConfig, listener: str,
                            arch: str = "x64", fmt: str = "exe",
                            sleep_secs: int | None = None) -> bytes:
    """Build a payload (blocking) and return the raw bytes.

    Combines ``payload build --wait`` with ``payload download`` into a
    single call.  A temporary file is used to receive the download and
    is deleted before returning.
    """
    import tempfile as _tempfile

    result = payload_build(cfg, listener=listener, arch=arch, fmt=fmt,
                           sleep_secs=sleep_secs, wait=True)
    payload_id = result["id"]

    with _tempfile.NamedTemporaryFile(delete=False, suffix=f".{fmt}") as tmp:
        tmp_path = tmp.name
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


def agent_exec(cfg: CliConfig, agent_id: str, cmd: str,
               wait: bool = True, timeout: int | None = None) -> dict:
    args = ["agent", "exec", agent_id, "--cmd", cmd]
    if wait:
        args.append("--wait")
    if timeout is not None:
        args += ["--timeout", str(timeout)]
    return _run(cfg, *args)


def agent_upload(cfg: CliConfig, agent_id: str, src: str, dst: str) -> dict:
    return _run(cfg, "agent", "upload", agent_id, "--src", src, "--dst", dst)


def agent_download(cfg: CliConfig, agent_id: str, src: str, dst: str) -> dict:
    return _run(cfg, "agent", "download", agent_id, "--src", src, "--dst", dst)


def agent_kill(cfg: CliConfig, agent_id: str) -> dict:
    return _run(cfg, "agent", "kill", agent_id, "--wait")


# ── Operators ────────────────────────────────────────────────────────────────

def operator_list(cfg: CliConfig) -> list[dict]:
    return _run(cfg, "operator", "list")


def operator_create(cfg: CliConfig, username: str, password: str, role: str) -> dict:
    return _run(cfg, "operator", "create", username,
                "--password", password, "--role", role)


def operator_delete(cfg: CliConfig, username: str) -> dict:
    return _run(cfg, "operator", "delete", username)


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
    if limit is not None:
        args += ["--limit", str(limit)]
    return _run(cfg, *args)
