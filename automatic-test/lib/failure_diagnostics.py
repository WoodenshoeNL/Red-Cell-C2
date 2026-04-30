"""
Capture teamserver-oriented diagnostics when a scenario fails.

Used by ``test.py`` to write
``test-results/YYYY-MM-DD/run_<HHMMSS>_<uuid>/scenario_NN_failure.txt``
and print the same sections to stdout.

Also writes a per-scenario diagnostic bundle at failure time:
``test-results/YYYY-MM-DD/run_<HHMMSS>_<uuid>/scenario_NN_diag/``
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
    agent_show,
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
    scenario_active_pass: str | None = None,
    scenario_stdout_tail: str | None = None,
    scenario_stderr_tail: str | None = None,
    harness_output_max_chars: int = 24_576,
) -> str:
    """Assemble the full diagnostic text written to the failure file and printed.

    *scenario_active_pass* — optional label from matrix scenarios (e.g. ``"demon"``,
    ``"specter"``) set on the harness ``RunContext`` while a pass runs.

    *scenario_stdout_tail* / *scenario_stderr_tail* — bounded tails of harness
    process streams while the scenario executed (typically the last
    *harness_output_max_chars* characters per stream).
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    err_txt = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

    def _cap_tail(text: str | None) -> str:
        if not text:
            return ""
        if len(text) <= harness_output_max_chars:
            return text
        return text[-harness_output_max_chars:]

    log_tail = capture_server_logs(ctx, lines=log_lines)
    agents_txt, raw_listeners, listeners_txt, audit_txt = _gather_cli_snapshot(ctx.cli)
    request_diag = _listener_request_summary(ctx.cli, raw_listeners)

    parts = [
        "Red Cell C2 — scenario failure diagnostic",
        f"Scenario: {scenario_id} — {scenario_title}",
        f"Captured (UTC): {ts}",
        "",
    ]

    if scenario_active_pass:
        parts.extend(
            [
                "=== SCENARIO CONTEXT ===",
                f"Active agent pass: {scenario_active_pass}",
                "",
            ]
        )

    out_tail = _cap_tail(scenario_stdout_tail)
    if out_tail.strip():
        parts.extend(
            [
                "=== SCENARIO STDOUT TAIL (harness) ===",
                out_tail.rstrip("\n"),
                "",
            ]
        )

    err_harness_tail = _cap_tail(scenario_stderr_tail)
    if err_harness_tail.strip():
        parts.extend(
            [
                "=== SCENARIO STDERR TAIL (harness) ===",
                err_harness_tail.rstrip("\n"),
                "",
            ]
        )

    parts.extend(
        [
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
    )
    return "\n".join(parts) + "\n"


def _build_agent_state(cli: CliConfig) -> dict:
    """Collect per-agent state snapshot from the CLI.

    Returns a dict suitable for JSON serialisation.  All CLI errors are caught
    and recorded inline so a partial failure does not suppress other agents.
    """
    try:
        agents = agent_list(cli)
    except CliError as exc:
        return {"error": f"agent list failed: [{exc.code}] {exc.message}", "agents": []}

    per_agent = []
    for entry in agents:
        agent_id = entry.get("id") or entry.get("AgentID") or entry.get("agent_id")
        if not agent_id:
            per_agent.append({"raw": entry, "error": "no id field"})
            continue

        record: dict[str, Any] = {"id": agent_id}

        # Populate what's in the list entry first.
        record.update(entry)

        # Enrich with per-agent detail.
        try:
            detail = agent_show(cli, str(agent_id))
            record["detail"] = detail
        except CliError as exc:
            record["detail_error"] = f"[{exc.code}] {exc.message}"

        # Fetch the last 20 audit entries for this specific agent.
        try:
            agent_audit = log_list(cli, agent_id=str(agent_id), limit=20)
            record["audit_tail"] = agent_audit
        except CliError as exc:
            record["audit_tail_error"] = f"[{exc.code}] {exc.message}"

        per_agent.append(record)

    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "seq_num/ECDH-state/packet ring-buffer not exposed by CLI API; "
            "query the SQLite DB column last_seen_seq in ts_agents for raw seq info"
        ),
        "agents": per_agent,
    }


def _build_teamserver_state(cli: CliConfig) -> dict:
    """Collect a teamserver-side snapshot: agents, listeners, audit tail, log tail."""
    ts = datetime.now(timezone.utc).isoformat()

    try:
        agents = agent_list(cli)
    except CliError as exc:
        agents = [{"error": f"[{exc.code}] {exc.message}"}]

    raw_listeners: list[dict] = []
    listeners_with_detail: list[dict] = []
    try:
        raw_listeners = listener_list(cli)
    except CliError as exc:
        listeners_with_detail = [{"error": f"[{exc.code}] {exc.message}"}]

    for lsnr in raw_listeners:
        name = lsnr.get("name", "")
        entry = dict(lsnr)
        if name:
            try:
                entry["detail"] = listener_show(cli, name)
            except CliError as exc:
                entry["detail_error"] = f"[{exc.code}] {exc.message}"
        listeners_with_detail.append(entry)

    try:
        audit = log_list(cli, limit=50)
    except CliError as exc:
        audit = [{"error": f"[{exc.code}] {exc.message}"}]

    try:
        log_entries = log_server_tail(cli, lines=200)
        log_tail = "\n".join(
            f"{e.get('timestamp', '?')}  {e.get('text', '')}" for e in log_entries
        )
    except CliError as exc:
        log_tail = f"(log server-tail failed: [{exc.code}] {exc.message})"

    return {
        "captured_at": ts,
        "agents": agents,
        "listeners": listeners_with_detail,
        "audit_log_tail": audit,
        "server_log_tail": log_tail,
    }


def _build_timeline(
    audit_log: list[dict],
    server_log_tail: str,
    harness_stdout: str | None,
    harness_stderr: str | None,
) -> str:
    """Merge audit log, server log lines, and harness output into a readable timeline.

    Items that carry a timestamp are sorted chronologically.  Harness output is
    appended at the end (it carries no per-line timestamps).
    """
    lines: list[tuple[str, str]] = []  # (iso-ish timestamp, text)

    for entry in audit_log:
        ts = str(entry.get("ts") or entry.get("timestamp") or "")
        parts = []
        for key in ("action", "operator", "agent_id", "detail", "result_status"):
            val = entry.get(key)
            if val:
                parts.append(f"{key}={val}")
        text = "  ".join(parts) if parts else str(entry)
        lines.append((ts, f"[AUDIT] {text}"))

    for raw_line in server_log_tail.splitlines():
        # Server log lines look like "2026-04-30T10:43:57Z  <text>" or "<text>".
        stripped = raw_line.strip()
        if not stripped:
            continue
        parts_split = stripped.split(None, 1)
        if len(parts_split) == 2 and "T" in parts_split[0] and ":" in parts_split[0]:
            ts, text = parts_split
        else:
            ts, text = "", stripped
        lines.append((ts, f"[SERVER] {text}"))

    # Sort by timestamp; empty timestamps sort last so they appear at the top
    # of the "no timestamp" group rather than pushing out timestamped entries.
    lines.sort(key=lambda t: (t[0] == "", t[0]))

    result_parts = ["=== TIMELINE (audit + server log, chronological) ===", ""]
    for _ts, text in lines:
        prefix = f"{_ts}  " if _ts else "                     "
        result_parts.append(f"{prefix}{text}")

    if harness_stdout and harness_stdout.strip():
        result_parts.extend(["", "=== HARNESS STDOUT (at failure) ===", harness_stdout.rstrip()])

    if harness_stderr and harness_stderr.strip():
        result_parts.extend(["", "=== HARNESS STDERR (at failure) ===", harness_stderr.rstrip()])

    result_parts.append("")
    return "\n".join(result_parts)


def write_scenario_diag_bundle(
    run_dir: Path,
    scenario_id: str,
    ctx: DiagnosticContext,
    *,
    harness_stdout: str | None = None,
    harness_stderr: str | None = None,
) -> Path:
    """Write a per-scenario diagnostic bundle to ``<run_dir>/scenario_<id>_diag/``.

    Creates four artifacts:

    * ``agent_state.json``     — per-agent info + per-agent audit tail
    * ``teamserver_state.json``— full agent registry, listener detail, audit tail, server log
    * ``timeline.txt``         — chronological merge of audit log + server log + harness output
    * ``last_packets.bin``     — empty placeholder (raw packet ring-buffer not exposed by CLI)

    All CLI errors are caught and embedded as ``"error"`` fields so a partial
    failure never suppresses the rest of the bundle.

    Returns the path to the created directory.
    """
    diag_dir = run_dir / f"scenario_{scenario_id}_diag"
    diag_dir.mkdir(parents=True, exist_ok=True)

    # ── agent_state.json ─────────────────────────────────────────────────────
    agent_state = _build_agent_state(ctx.cli)
    (diag_dir / "agent_state.json").write_text(
        _safe_json_dump(agent_state), encoding="utf-8"
    )

    # ── teamserver_state.json ─────────────────────────────────────────────────
    ts_state = _build_teamserver_state(ctx.cli)
    (diag_dir / "teamserver_state.json").write_text(
        _safe_json_dump(ts_state), encoding="utf-8"
    )

    # ── timeline.txt ──────────────────────────────────────────────────────────
    # Reuse the audit log and server log already fetched for teamserver_state
    # to avoid double-querying the server.
    audit_log = ts_state.get("audit_log_tail") or []
    if not isinstance(audit_log, list):
        audit_log = []
    server_log_tail = ts_state.get("server_log_tail") or ""
    timeline = _build_timeline(audit_log, server_log_tail, harness_stdout, harness_stderr)
    (diag_dir / "timeline.txt").write_text(timeline, encoding="utf-8")

    # ── last_packets.bin ──────────────────────────────────────────────────────
    # The CLI API does not expose raw packet ring buffers.  Write an empty file
    # so the expected artifact is always present; future server-side work can
    # populate it when a /debug/packet-ring endpoint is added.
    (diag_dir / "last_packets.bin").write_bytes(b"")

    return diag_dir.resolve()


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
