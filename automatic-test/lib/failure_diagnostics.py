"""
Capture teamserver-oriented diagnostics when a scenario fails.

Used by ``test.py`` to write
``test-results/YYYY-MM-DD/run_<HHMMSS>_<uuid>/scenario_NN_failure.txt``
and print the same sections to stdout.
"""

from __future__ import annotations

import json
import os
import traceback
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .cli import (
    CliConfig,
    CliError,
    agent_list,
    listener_list,
    listener_show,
    log_list,
    log_server_tail,
)


@runtime_checkable
class DiagnosticContext(Protocol):
    """Minimal context shape for :func:`capture_server_logs`."""

    cli: CliConfig
    env: dict[str, Any]


def tail_text_file(path: Path, max_lines: int) -> str:
    """Return the last *max_lines* lines of *path* as a string (UTF-8, replace errors).

    Public for unit tests. Returns an explanatory message if the file cannot be read.
    """
    if max_lines <= 0:
        return ""
    try:
        with open(path, "rb") as fh:
            last = deque(fh, maxlen=max_lines)
    except OSError as exc:
        return f"(could not read log file {path}: {exc})"
    text = b"".join(last).decode("utf-8", errors="replace")
    if text and not text.endswith("\n"):
        text += "\n"
    return text


def capture_server_logs(ctx: DiagnosticContext, lines: int = 100) -> str:
    """Return the last *lines* of teamserver process logs when configured.

    Resolution order:

    1. ``env["teamserver"]["log_file"]`` — path on the machine running ``test.py``
       (typical when teamserver runs on the same host and logs to a file).
    2. CLI ``red-cell-cli log server-tail --lines N`` — fetches from the
       teamserver's debug endpoint using the operator credentials already
       configured in ``ctx.cli``.

    If neither is available, returns guidance to configure ``log_file``.
    """
    teamserver = ctx.env.get("teamserver") or {}
    if not isinstance(teamserver, dict):
        teamserver = {}

    log_file = teamserver.get("log_file")
    if log_file:
        p = Path(str(log_file)).expanduser()
        if p.is_file():
            return tail_text_file(p, lines)
        return f"(log_file path does not exist or is not a file: {p})"

    return _fetch_log_tail_cli(ctx.cli, lines)


def _fetch_log_tail_cli(cli: CliConfig, lines: int) -> str:
    """Fetch teamserver log tail via ``red-cell-cli log server-tail``."""
    try:
        entries = log_server_tail(cli, lines)
    except CliError as exc:
        return f"(log server-tail failed: [{exc.code}] {exc.message})"

    if not entries:
        return "(no log entries returned by server-tail)\n"

    text_lines = [f"{e.get('timestamp', '?')}  {e.get('text', '')}" for e in entries]
    return "\n".join(text_lines) + "\n"


def _safe_json_dump(data: Any) -> str:
    try:
        return json.dumps(data, indent=2, default=str, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        return f"(could not serialize: {exc})\n{data!r}"


def _listener_request_summary(
    cli: CliConfig, listeners: list[dict],
) -> str:
    """Build a diagnostic block with per-listener errors and agent registration counts.

    This answers the single most important triage question: did the listener
    receive ANY incoming requests during the scenario?
    """
    lines: list[str] = []

    for listener in listeners:
        name = listener.get("name", "?")
        status = listener.get("status", "?")
        lines.append(f"Listener '{name}' (status={status}):")
        try:
            detail = listener_show(cli, name)
            last_error = detail.get("last_error")
            if last_error:
                lines.append(f"  last_error: {last_error}")
            else:
                lines.append("  last_error: (none)")
        except CliError as exc:
            lines.append(f"  last_error: (query failed: [{exc.code}] {exc.message})")

    try:
        registrations = log_list(cli, action="agent.registered", limit=200)
        lines.append(f"\nAgent registrations (total): {len(registrations)}")
        if registrations:
            last = registrations[0]
            lines.append(f"  Most recent: ts={last.get('ts', '?')}  agent={last.get('agent_id', '?')}")
    except CliError as exc:
        lines.append(f"\nAgent registrations: (query failed: [{exc.code}] {exc.message})")

    try:
        reregistrations = log_list(cli, action="agent.reregistered", limit=200)
        if reregistrations:
            lines.append(f"Agent re-registrations (total): {len(reregistrations)}")
    except CliError:
        pass

    return "\n".join(lines)


def _gather_cli_snapshot(cli: CliConfig) -> tuple[str, list[dict], str, str]:
    """Return formatted agents, raw listeners, formatted listeners, and audit log."""
    try:
        agents = agent_list(cli)
        agents_txt = _safe_json_dump(agents)
    except CliError as exc:
        agents_txt = f"(agent list failed: [{exc.code}] {exc.message})"

    raw_listeners: list[dict] = []
    try:
        raw_listeners = listener_list(cli)
        listeners_txt = _safe_json_dump(raw_listeners)
    except CliError as exc:
        listeners_txt = f"(listener list failed: [{exc.code}] {exc.message})"

    try:
        audit = log_list(cli, limit=20)
        audit_txt = _safe_json_dump(audit)
    except CliError as exc:
        audit_txt = f"(audit log list failed: [{exc.code}] {exc.message})"

    return agents_txt, raw_listeners, listeners_txt, audit_txt


def build_failure_diagnostic_report(
    ctx: DiagnosticContext,
    scenario_id: str,
    scenario_title: str,
    exc: BaseException,
    *,
    log_lines: int = 100,
) -> str:
    """Assemble the full diagnostic text written to the failure file and printed."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    err_txt = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

    log_tail = capture_server_logs(ctx, lines=log_lines)
    agents_txt, raw_listeners, listeners_txt, audit_txt = _gather_cli_snapshot(ctx.cli)
    request_diag = _listener_request_summary(ctx.cli, raw_listeners)

    parts = [
        "Red Cell C2 — scenario failure diagnostic",
        f"Scenario: {scenario_id} — {scenario_title}",
        f"Captured (UTC): {ts}",
        "",
        "=== EXCEPTION ===",
        err_txt.rstrip("\n"),
        "",
        "=== TEAMSERVER LOG TAIL ===",
        log_tail.rstrip("\n"),
        "",
        "=== ACTIVE AGENTS ===",
        agents_txt,
        "",
        "=== ACTIVE LISTENERS ===",
        listeners_txt,
        "",
        "=== LISTENER REQUEST DIAGNOSTICS ===",
        request_diag,
        "",
        "=== RECENT AUDIT LOG (last 20) ===",
        audit_txt,
        "",
    ]
    return "\n".join(parts) + "\n"


def create_run_dir(automatic_test_root: Path) -> Path:
    """Create and return a per-run subfolder under ``test-results/<date>/``.

    The folder name is ``run_<HHMMSS>_<short-uuid>`` so multiple runs on the
    same day never collide.  A ``test-results/latest`` symlink is updated to
    point at the new directory.
    """
    now = datetime.now(timezone.utc)
    day = now.strftime("%Y-%m-%d")
    tag = now.strftime("%H%M%S") + "_" + uuid.uuid4().hex[:8]
    run_dir = automatic_test_root / "test-results" / day / f"run_{tag}"
    run_dir.mkdir(parents=True, exist_ok=True)

    latest = automatic_test_root / "test-results" / "latest"
    try:
        tmp = latest.with_suffix(".tmp")
        tmp.unlink(missing_ok=True)
        os.symlink(run_dir.resolve(), tmp)
        os.replace(tmp, latest)
    except OSError:
        pass

    return run_dir


def write_scenario_failure_file(
    run_dir: Path,
    scenario_id: str,
    text: str,
) -> Path:
    """Write *text* under ``<run_dir>/scenario_<id>_failure.txt``."""
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / f"scenario_{scenario_id}_failure.txt"
    path.write_text(text, encoding="utf-8")
    return path.resolve()
