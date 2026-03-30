#!/usr/bin/env python3
"""
smoke-test.py — Fast pre-flight check for the Red Cell C2 teamserver.

Verifies that:
  1. The teamserver is reachable (status endpoint responds)
  2. Operator authentication works (login succeeds)
  3. Listener lifecycle works (create → start → stop → delete)

This is intentionally minimal — it does NOT deploy agents or require test
machines. Run it before a full test harness run to catch configuration problems
early, or after a teamserver restart to confirm it is healthy.

Usage:
    python3 smoke-test.py
    python3 smoke-test.py --config-dir path/to/config

Config:
    config/env.toml  — server URL + operator credentials (same as test.py)

Exit codes:
    0  all checks passed
    1  one or more checks failed
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from lib.cli import CliConfig, CliError, status, login, \
    listener_list, listener_create, listener_start, listener_stop, listener_delete


# ── Helpers ──────────────────────────────────────────────────────────────────

def _pass(msg: str) -> None:
    print(f"  ✓  {msg}")


def _fail(msg: str) -> None:
    print(f"  ✗  {msg}")


# ── Checks ───────────────────────────────────────────────────────────────────

_REQUIRED_TOOLS = [
    ("x86_64-w64-mingw32-gcc", ["x86_64-w64-mingw32-gcc", "--version"]),
    ("nasm",                   ["nasm", "--version"]),
]


def check_toolchain(_cfg: CliConfig) -> bool:
    """Verify that payload-build toolchain tools are present on the host."""
    all_ok = True
    for name, cmd in _REQUIRED_TOOLS:
        if shutil.which(cmd[0]) is None:
            _fail(
                f"toolchain tool not found: {name!r}\n"
                f"       Install it (e.g. 'apt install {_install_hint(name)}') "
                f"before running payload scenarios."
            )
            all_ok = False
            continue
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            _pass(f"toolchain: {name} present")
        except subprocess.CalledProcessError as exc:
            _fail(
                f"toolchain tool '{name}' returned non-zero: {exc.returncode}\n"
                f"       {exc.stderr.decode(errors='replace').strip()}"
            )
            all_ok = False
    return all_ok


def _install_hint(tool_name: str) -> str:
    hints = {
        "x86_64-w64-mingw32-gcc": "mingw-w64",
        "nasm": "nasm",
    }
    return hints.get(tool_name, tool_name)


def check_server_reachable(cfg: CliConfig) -> bool:
    try:
        status(cfg)
        _pass(f"teamserver reachable at {cfg.server}")
        return True
    except CliError as exc:
        _fail(f"teamserver not reachable: {exc}")
        return False
    except Exception as exc:
        _fail(f"unexpected error reaching server: {exc}")
        return False


def check_auth(cfg: CliConfig) -> bool:
    try:
        token = login(cfg)
        if not token:
            _fail("login returned empty token")
            return False
        # Update the config with the real token for subsequent calls
        cfg.token = token
        _pass("authentication successful")
        return True
    except CliError as exc:
        _fail(f"authentication failed: {exc}")
        return False


def check_listener_lifecycle(cfg: CliConfig) -> bool:
    name = f"smoke-{int(time.time())}"
    try:
        listener_create(cfg, name=name, type_="http", port=44444)
        _pass(f"listener create ({name})")
    except CliError as exc:
        _fail(f"listener create failed: {exc}")
        return False

    try:
        listener_start(cfg, name)
        _pass("listener start")
    except CliError as exc:
        _fail(f"listener start failed: {exc}")
        # Still try to clean up
        try:
            listener_delete(cfg, name)
        except Exception:
            pass
        return False

    try:
        listener_stop(cfg, name)
        _pass("listener stop")
    except CliError as exc:
        _fail(f"listener stop failed: {exc}")
        try:
            listener_delete(cfg, name)
        except Exception:
            pass
        return False

    try:
        listener_delete(cfg, name)
        _pass("listener delete")
    except CliError as exc:
        _fail(f"listener delete failed: {exc}")
        return False

    return True


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Red Cell C2 smoke test")
    parser.add_argument(
        "--config-dir", type=Path,
        default=Path(__file__).parent / "config",
        help="Path to config directory containing env.toml",
    )
    args = parser.parse_args()

    config_path = args.config_dir / "env.toml"
    if not config_path.exists():
        print(f"[ERROR] Config not found: {config_path}")
        sys.exit(1)

    with open(config_path, "rb") as f:
        env = tomllib.load(f)

    cfg = CliConfig(
        server=env["server"]["url"],
        token=env["operator"]["password"],
        timeout=env.get("timeouts", {}).get("command_output", 30),
    )

    print()
    print("Red Cell C2 — smoke test")
    print(f"Server: {cfg.server}")
    print()

    checks = [
        ("Toolchain",              check_toolchain),
        ("Server reachable",       check_server_reachable),
        ("Authentication",         check_auth),
        ("Listener lifecycle",     check_listener_lifecycle),
    ]

    passed = 0
    failed = 0

    for label, fn in checks:
        print(f"[{label}]")
        ok = fn(cfg)
        if ok:
            passed += 1
        else:
            failed += 1
        print()

    print("─" * 40)
    print(f"  {passed} passed, {failed} failed")
    print("─" * 40)
    print()

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
