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

    result = subprocess.run(
        [cfg.binary, "--output", "json", "--timeout", str(cfg.timeout), *args],
        capture_output=True,
        text=True,
        env=env,
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
    """Authenticate and return a session token."""
    data = _run(cfg, "auth", "login",
                "--username", cfg.token,  # cfg.token holds the password pre-login
                "--server", cfg.server)
    return data["token"]


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

def payload_build(cfg: CliConfig, agent: str, listener: str,
                  arch: str = "x64", fmt: str = "exe",
                  output: str | None = None) -> dict:
    args = ["payload", "build",
            "--agent", agent,
            "--listener", listener,
            "--arch", arch,
            "--format", fmt]
    if output:
        args += ["--output", output]
    return _run(cfg, *args)


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
