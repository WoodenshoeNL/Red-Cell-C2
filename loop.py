#!/usr/bin/env python3
"""
loop.py — Unified agent loop runner for Red Cell C2

Replaces: claude_loop.sh, claude_arch_loop.sh, claude_dev_loop.sh,
          claude_test_loop.sh, codex_loop.sh, codex_arch_loop.sh,
          codex_qa_loop.sh, codex_test_loop.sh, cursor_loop.sh
"""

import argparse
import fcntl
import json
import os
import random
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


# ── Constants ──────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
LOG_DIR = SCRIPT_DIR / "logs"

# Default sleep between iterations (seconds) when --sleep is not specified
DEFAULT_SLEEP = {
    "dev":      0,
    "qa":       20 * 60,    # 20 minutes
    "arch":     120 * 60,   # 120 minutes
    "quality":  30 * 60,    # 30 minutes
    "coverage": 30 * 60,    # 30 minutes
}

# Dev loop timing constants (seconds)
DEV_SLEEP_NO_WORK     = 60     # wait when no tasks are ready
DEV_SLEEP_BETWEEN     = 15     # wait between tasks when --sleep not set
DEV_SLEEP_TOKEN_LIMIT = 1200   # wait after Claude context limit hit
DEV_CLEAN_EVERY       = 10     # run build-artifact cleanup every N dev iterations

# Valid zone names and their corresponding source paths
ZONES = {
    "client-cli": ["client-cli/"],
    "client":     ["client/"],
    "teamserver": ["teamserver/"],
    "common":     ["common/"],
    "agent":      ["agent/"],
}

# Dev loops use agent-specific prompts (Co-Authored-By differs per agent)
DEV_PROMPTS = {
    "claude": "prompts/CLAUDE_DEV_PROMPT.md",
    "codex":  "prompts/CODEX_PROMPT.md",
    "cursor": "prompts/CURSOR_PROMPT.md",
}

# Review loops use a single best-of prompt per loop type (agent-independent)
REVIEW_PROMPTS = {
    "qa":       "prompts/CLAUDE_PROMPT.md",        # identical across agents
    "arch":     "prompts/CLAUDE_ARCH_PROMPT.md",   # Claude version is more thorough
    "quality":  "prompts/CLAUDE_TEST_PROMPT.md",   # quality-focused test review
    "coverage": "prompts/CODEX_TEST_PROMPT.md",    # breadth-focused coverage scan
}

# Review loop types that write a per-run timestamped log in addition to the rolling log
PER_RUN_LOG_LOOPS = {"arch", "quality", "coverage"}


# ── Logging ────────────────────────────────────────────────────────────────────

class Logger:
    def __init__(self, agent_id: str, log_file: Path):
        self.agent_id = agent_id
        self.log_file = log_file
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    def _format(self, msg: str) -> str:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"[{ts}] [{self.agent_id}] {msg}"

    def log(self, msg: str):
        line = self._format(msg)
        print(line, flush=True)
        with open(self.log_file, "a") as f:
            f.write(line + "\n")

    def banner(self, lines: list):
        sep = "=" * 56
        self.log(sep)
        for line in lines:
            self.log(f"  {line}")
        self.log(sep)


# ── Stop signal ────────────────────────────────────────────────────────────────

def stop_requested() -> bool:
    return (SCRIPT_DIR / ".stop").exists()


# ── Git / Beads helpers ────────────────────────────────────────────────────────

def git(args: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(SCRIPT_DIR)] + args,
        capture_output=True, text=True, **kwargs
    )


def br(args: list) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["br"] + args,
        capture_output=True, text=True, cwd=str(SCRIPT_DIR)
    )


def git_pull_rebase(log: Logger) -> bool:
    r = git(["pull", "--rebase", "--quiet"])
    if r.returncode == 0:
        log.log("git pull --rebase: ok")
        return True
    log.log("WARNING: git pull --rebase failed, continuing with local state")
    return False


def git_pull_ff(log: Logger) -> bool:
    r = git(["pull", "--ff-only", "--quiet"])
    if r.returncode == 0:
        log.log("git pull --ff-only: ok")
        return True
    log.log("WARNING: git pull --ff-only failed")
    return False


# ── Agent invocation ───────────────────────────────────────────────────────────

def build_agent_cmd(agent: str, model: str) -> tuple:
    """
    Returns (cmd, uses_stdin).
    Claude and Codex read the prompt from stdin; Cursor takes it as a positional arg.
    """
    if agent == "claude":
        cmd = ["claude", "-p", "--dangerously-skip-permissions", "--verbose", "--output-format", "stream-json"]
        if model:
            cmd += ["--model", model]
        return cmd, True

    if agent == "codex":
        return ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox"], True

    if agent == "cursor":
        # prompt is injected as positional arg at call time
        return [
            "agent", "--print", "--yolo", "--trust", "--approve-mcps",
            "--workspace", str(SCRIPT_DIR),
        ], False

    raise ValueError(f"Unknown agent: {agent}")


def run_agent(
    agent: str,
    model: str,
    prompt_content: str,
    log: Logger,
    extra_log_file: Path = None,
) -> tuple:
    """
    Run the agent with prompt_content. Streams output to terminal and log files.
    Returns (exit_code, full_output_text).

    For claude (stream-json mode): raw JSON is written to log files; human-readable
    tool/text events are printed to the terminal. The returned text is the extracted
    final response from the result event.
    """
    cmd, uses_stdin = build_agent_cmd(agent, model)
    is_stream_json = agent == "claude"

    if not uses_stdin:
        # Cursor: prompt is the final positional argument
        proc = subprocess.Popen(
            cmd + [prompt_content],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd=str(SCRIPT_DIR),
        )
    else:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd=str(SCRIPT_DIR),
        )

        def _write_stdin():
            try:
                proc.stdin.write(prompt_content)
                proc.stdin.close()
            except BrokenPipeError:
                pass

        threading.Thread(target=_write_stdin, daemon=True).start()

    log_handles = [open(log.log_file, "a")]
    if extra_log_file:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_handles.append(open(extra_log_file, "w"))

    raw_lines = []
    try:
        for line in proc.stdout:
            # Always write raw line to log files
            for fh in log_handles:
                fh.write(line)
                fh.flush()
            raw_lines.append(line)

            if is_stream_json:
                stripped = line.strip()
                if stripped:
                    try:
                        event = json.loads(stripped)
                        formatted = format_stream_event(event)
                        if formatted is not None:
                            print(formatted, flush=True)
                    except json.JSONDecodeError:
                        print(line, end="", flush=True)
            else:
                print(line, end="", flush=True)
    finally:
        for fh in log_handles:
            fh.close()

    proc.wait()

    if is_stream_json:
        return proc.returncode, extract_text_from_stream(raw_lines)
    return proc.returncode, "".join(raw_lines)


# ── Sleep with jitter ──────────────────────────────────────────────────────────

def do_sleep(seconds: float, jitter_seconds: float, log: Logger):
    if seconds <= 0 and jitter_seconds <= 0:
        return

    if jitter_seconds > 0:
        delta = random.uniform(-jitter_seconds, jitter_seconds)
        actual = max(0.0, seconds + delta)
    else:
        actual = seconds

    if actual <= 0:
        return

    wake_str = datetime.fromtimestamp(time.time() + actual).strftime("%H:%M:%S")
    mins = actual / 60
    if jitter_seconds > 0:
        log.log(
            f"Next run in {mins:.0f}m (at {wake_str})"
            f"  [jitter ±{jitter_seconds/60:.0f}m applied]"
        )
    else:
        log.log(f"Next run in {mins:.0f}m (at {wake_str})")

    time.sleep(actual)


# ── Output parsing ────────────────────────────────────────────────────────────

def extract_session_summary(output: str) -> list:
    """
    Extract the structured session summary block from agent output.
    Returns a list of lines between === SESSION SUMMARY === and === END SUMMARY ===,
    or an empty list if no summary block is found.
    """
    lines = output.splitlines()
    in_summary = False
    result = []
    for line in lines:
        stripped = line.strip()
        if "=== SESSION SUMMARY ===" in stripped:
            in_summary = True
            continue
        if "=== END SUMMARY ===" in stripped:
            break
        if in_summary and stripped:
            result.append(stripped)
    return result


def format_stream_event(event: dict) -> str | None:
    """
    Convert a claude stream-json event to a human-readable line.
    Returns None for events that should be silently skipped.
    """
    t = event.get("type", "")

    if t == "tool_use":
        name = event.get("name", "?")
        inp = event.get("input", {})
        if name == "Read":
            detail = inp.get("file_path", "?")
        elif name == "Bash":
            detail = inp.get("command", "?").strip().replace("\n", "; ")[:120]
        elif name == "Grep":
            detail = f"'{inp.get('pattern', '')}' in {inp.get('path', inp.get('directory', '.'))}"
        elif name == "Glob":
            detail = inp.get("pattern", "?")
        elif name in ("Edit", "Write"):
            detail = inp.get("file_path", "?")
        elif name == "Agent":
            detail = inp.get("description", inp.get("prompt", "?"))[:100]
        else:
            detail = str(inp)[:100]
        return f"  [{name}] {detail}"

    if t == "assistant":
        texts = [
            b.get("text", "")
            for b in event.get("message", {}).get("content", [])
            if b.get("type") == "text"
        ]
        combined = " ".join(texts).strip()
        return combined if combined else None

    if t == "result":
        subtype = event.get("subtype", "unknown")
        duration = event.get("duration_ms", 0) / 1000
        cost = event.get("total_cost_usd", 0)
        turns = event.get("num_turns", "?")
        return f"  [result] {subtype} — {turns} turns, {duration:.0f}s, ${cost:.4f}"

    return None  # skip system, tool_result, etc.


def extract_text_from_stream(raw_lines: list) -> str:
    """
    Extract the final text response from a claude stream-json session.
    Pulls from the 'result' event, falling back to concatenated assistant text blocks.
    """
    for line in reversed(raw_lines):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
            if event.get("type") == "result":
                return event.get("result", "")
        except json.JSONDecodeError:
            pass
    # Fallback: collect assistant text blocks in order
    texts = []
    for line in raw_lines:
        try:
            event = json.loads(line.strip())
            if event.get("type") == "assistant":
                for block in event.get("message", {}).get("content", []):
                    if block.get("type") == "text":
                        texts.append(block.get("text", ""))
        except json.JSONDecodeError:
            pass
    return "\n".join(texts)


# ── Dev loop helpers ───────────────────────────────────────────────────────────

def issue_status_from_jsonl(task_id: str) -> str:
    """Read the last status entry for task_id directly from the JSONL file."""
    jsonl = SCRIPT_DIR / ".beads" / "issues.jsonl"
    if not jsonl.exists():
        return ""
    last = None
    try:
        with open(jsonl) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    if e.get("id") == task_id:
                        last = e
                except json.JSONDecodeError:
                    pass
        return (last or {}).get("status", "")
    except Exception:
        return ""


def issue_status(task_id: str) -> str:
    """Query issue status via the br CLI."""
    r = br(["show", task_id, "--json"])
    if r.returncode != 0:
        return ""
    try:
        issues = json.loads(r.stdout)
        if issues:
            return issues[0].get("status", "")
    except Exception:
        pass
    return ""


def repair_db_if_needed(log: Logger, rename_prefix: bool):
    """Rebuild the beads SQLite DB from JSONL if schema drift is detected."""
    r = br(["stats", "--json"])
    combined = r.stdout + r.stderr
    if '"DATABASE_ERROR"' not in combined:
        return
    log.log("DB schema error detected — rebuilding from JSONL")
    db = SCRIPT_DIR / ".beads" / "beads.db"
    for suffix in ("", "-wal", "-shm"):
        Path(str(db) + suffix).unlink(missing_ok=True)
    args = ["sync", "--import-only", "--quiet"]
    if rename_prefix:
        args.insert(2, "--rename-prefix")
    r = br(args)
    if r.returncode == 0:
        log.log("DB rebuilt successfully")
    else:
        log.log("WARNING: DB rebuild failed")


def clean_build_artifacts(log: Logger):
    """
    Remove stale Rust build artifacts to keep target/debug from growing unboundedly.

    Strategy (in order of preference):
    1. cargo sweep --time 1  — removes files unused for >24 h, keeps active artifacts
    2. Fallback: delete target/debug/incremental entirely (always safe; just slows
       the next incremental build slightly)

    Called after every review-loop iteration and every DEV_CLEAN_EVERY dev iterations.
    """
    import shutil

    target_debug = SCRIPT_DIR / "target" / "debug"
    if not target_debug.exists():
        return

    # Prefer cargo-sweep: surgical, keeps recently-used deps and incremental data
    if subprocess.run(["which", "cargo-sweep"], capture_output=True).returncode == 0:
        r = subprocess.run(
            ["cargo", "sweep", "--time", "1"],
            capture_output=True, text=True, cwd=str(SCRIPT_DIR),
        )
        if r.returncode == 0:
            log.log("build cache: cargo sweep --time 1 ok")
            return
        log.log(f"build cache: cargo sweep failed ({r.stderr.strip()[:80]}) — falling back")

    # Fallback: nuke incremental (31 GB in practice; always safe to delete)
    incremental = target_debug / "incremental"
    if incremental.exists():
        try:
            shutil.rmtree(incremental)
            log.log("build cache: removed target/debug/incremental")
        except OSError as e:
            log.log(f"build cache: could not remove incremental: {e}")


def reset_stuck_tasks(log: Logger, stale_threshold_secs: int):
    """Reset any in_progress tasks that have been stuck longer than the threshold."""
    r = br(["list", "--status=in_progress", "--json"])
    if r.returncode != 0:
        return
    try:
        issues = json.loads(r.stdout)
    except Exception:
        return
    now = datetime.now(timezone.utc)
    for issue in issues:
        ts = issue.get("updated_at") or issue.get("created_at", "")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if (now - dt).total_seconds() > stale_threshold_secs:
                tid = issue["id"]
                log.log(
                    f"SAFEGUARD: {tid} stuck in_progress for"
                    f" >{stale_threshold_secs}s — resetting to open"
                )
                r2 = br(["update", tid, "--status=open"])
                if r2.returncode == 0:
                    log.log(f"SAFEGUARD: {tid} reset to open")
                else:
                    log.log(f"WARNING: failed to reset {tid}")
        except ValueError:
            pass


def find_resumable_task(agent_id: str) -> str:
    """
    Find a task this agent previously claimed that is still in_progress.
    Used to resume interrupted sessions without creating a second claim commit.
    """
    r = br(["list", "--status=in_progress", "--json"])
    if r.returncode != 0:
        return ""
    try:
        issues = json.loads(r.stdout)
    except Exception:
        return ""
    for issue in issues:
        tid = issue["id"]
        r2 = git([
            "log", "--oneline",
            f"--grep=chore: claim {tid} [{agent_id}]",
            "--max-count=1",
        ])
        if r2.stdout.strip():
            return tid
    return ""


def claim_task(task_id: str, agent_id: str, log: Logger, rename_prefix: bool) -> bool:
    """
    Claim a task with optimistic git locking.
    Pushes the claim commit immediately so other agents see it.
    Returns True on success, False if another agent beat us or something went wrong.
    """
    r = git(["rev-parse", "HEAD"])
    if r.returncode != 0:
        return False
    head_before = r.stdout.strip()

    # Bypass stale DB: check JSONL directly to detect double-claim
    if issue_status_from_jsonl(task_id) == "in_progress":
        log.log(
            f"CLAIM SKIP: {task_id} already in_progress in JSONL"
            f" (stale DB) — forcing DB rebuild"
        )
        db = SCRIPT_DIR / ".beads" / "beads.db"
        for suffix in ("", "-wal", "-shm"):
            Path(str(db) + suffix).unlink(missing_ok=True)
        args = ["sync", "--import-only", "--quiet"]
        if rename_prefix:
            args.insert(2, "--rename-prefix")
        br(args)
        return False

    if br(["update", task_id, "--status=in_progress"]).returncode != 0:
        return False
    if br(["sync", "--flush-only"]).returncode != 0:
        return False

    # If JSONL didn't change, another agent's state may have already overwritten it
    if git(["diff", "--quiet", "--", ".beads/issues.jsonl"]).returncode == 0:
        log.log(f"CLAIM SKIP: {task_id} produced no JSONL change — refreshing")
        args = ["sync", "--import-only", "--quiet"]
        if rename_prefix:
            args.insert(2, "--rename-prefix")
        br(args)
        return False

    git(["add", ".beads/issues.jsonl"])
    if git(["commit", "-m", f"chore: claim {task_id} [{agent_id}]", "--quiet"]).returncode != 0:
        log.log(f"CLAIM SKIP: failed to create claim commit for {task_id}")
        git(["restore", "--staged", ".beads/issues.jsonl"])
        git(["checkout", "--", ".beads/issues.jsonl"])
        args = ["sync", "--import-only", "--quiet"]
        if rename_prefix:
            args.insert(2, "--rename-prefix")
        br(args)
        return False

    r = git(["rev-parse", "HEAD"])
    claim_commit = r.stdout.strip() if r.returncode == 0 else ""

    if git(["push", "--quiet"]).returncode == 0:
        git(["pull", "--ff-only", "--quiet"])
        args = ["sync", "--import-only", "--quiet"]
        if rename_prefix:
            args.insert(2, "--rename-prefix")
        br(args)

        # Verify claim commit is still reachable (no force-push from another agent)
        if claim_commit:
            r2 = git(["merge-base", "--is-ancestor", claim_commit, "HEAD"])
            if r2.returncode != 0:
                log.log(f"CLAIM VERIFY FAILED: claim commit for {task_id} no longer on branch")
                return False

        final = issue_status(task_id)
        if final != "in_progress":
            log.log(
                f"CLAIM VERIFY FAILED: {task_id} expected in_progress,"
                f" got '{final or 'unknown'}'"
            )
            return False

        return True

    # Push failed — another agent pushed first
    log.log(f"CLAIM CONFLICT: another agent claimed {task_id} first — releasing")
    git(["reset", head_before, "--mixed", "--quiet"])
    git(["checkout", "--", ".beads/issues.jsonl"])
    git(["pull", "--ff-only", "--quiet"])
    args = ["sync", "--import-only", "--quiet"]
    if rename_prefix:
        args.insert(2, "--rename-prefix")
    br(args)
    return False


def normalize_codex_ids(log: Logger, agent_id: str):
    """
    Codex-only: normalise any red-xxx IDs to red-cell-c2-xxx prefix.
    Runs after br sync --import-only --rename-prefix may have updated the DB.
    """
    if br(["sync", "--flush-only", "--quiet"]).returncode == 0:
        return
    if br(["sync", "--flush-only", "--force", "--quiet"]).returncode != 0:
        return
    if git(["diff", "--quiet", "--", ".beads/issues.jsonl"]).returncode == 0:
        return  # nothing changed
    git(["add", ".beads/issues.jsonl"])
    r = git([
        "commit", "-m",
        f"chore: normalize issue IDs to red-cell-c2 prefix [{agent_id}]",
        "--quiet",
    ])
    if r.returncode == 0:
        if git(["push", "--quiet"]).returncode == 0:
            log.log("Normalized issue IDs in JSONL and pushed")
        else:
            log.log("WARNING: could not push normalized JSONL")


# ── Dev loop ───────────────────────────────────────────────────────────────────

def dev_loop(args, log: Logger):
    agent = args.agent
    rename_prefix = (agent == "codex")
    agent_id = f"{socket.gethostname()}-{agent}"
    stale_secs = args.stale_threshold * 60

    # Sleep between tasks: use --sleep if given, else DEV_SLEEP_BETWEEN
    if args.sleep is not None:
        sleep_secs = args.sleep * 60
    else:
        sleep_secs = DEV_SLEEP_BETWEEN
    jitter_secs = args.jitter * 60

    prompt_file = SCRIPT_DIR / DEV_PROMPTS[agent]
    if not prompt_file.exists():
        log.log(f"ERROR: {prompt_file} not found. Exiting.")
        sys.exit(1)

    zones = args.zone or []
    max_iters = args.iterations
    iteration = 0

    zone_desc = ", ".join(zones) if zones else "all zones"
    log.banner([
        f"{agent.title()} development loop starting",
        f"Agent ID:  {agent_id}",
        f"Prompt:    {prompt_file.name}",
        f"Log:       {log.log_file.name}",
        f"Max runs:  {'unlimited' if max_iters == 0 else max_iters}",
        f"Stale thr: {args.stale_threshold}m",
        f"Zones:     {zone_desc}",
    ])

    lock_path = SCRIPT_DIR / ".agent-claim.lock"
    lock_fd = open(lock_path, "w")

    while True:
        if stop_requested():
            log.log("STOP signal detected (.stop file exists). Exiting.")
            sys.exit(0)

        if max_iters > 0 and iteration >= max_iters:
            log.log(f"Reached max iterations ({max_iters}). Exiting.")
            sys.exit(0)

        label = f"{iteration + 1} of {max_iters}" if max_iters > 0 else str(iteration + 1)
        log.log(f"=== {agent.title()} dev loop iteration {label} ===")
        iteration += 1

        # Acquire local claim lock (non-blocking)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log.log("WARNING: failed to acquire local claim lock")
            time.sleep(DEV_SLEEP_NO_WORK)
            continue

        if not git_pull_ff(log):
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            time.sleep(DEV_SLEEP_NO_WORK)
            continue

        # Sync issues from remote
        sync_args = ["sync", "--import-only", "--quiet"]
        if rename_prefix:
            sync_args.insert(2, "--rename-prefix")
        r = br(sync_args)
        log.log("br sync import: ok" if r.returncode == 0 else "WARNING: br sync import failed, continuing")

        if rename_prefix:
            normalize_codex_ids(log, agent_id)

        repair_db_if_needed(log, rename_prefix)
        reset_stuck_tasks(log, stale_secs)

        # Find the next task to work on
        next_id = ""

        # Claude only: resume a task interrupted in a prior session
        if agent == "claude":
            next_id = find_resumable_task(agent_id)
            if next_id:
                log.log(f"Resuming previously claimed task {next_id} (skipping re-claim)")

        if not next_id:
            r = br(["ready", "--json"])
            candidates = []
            if r.returncode == 0:
                try:
                    issues = json.loads(r.stdout)
                    # Apply zone filter if specified.
                    # br ready --json omits labels, so cross-reference with
                    # br list --status=open --json which includes them.
                    if zones:
                        zone_labels = {f"zone:{z}" for z in zones}
                        # br ready caps at 20; re-query with a high limit so
                        # lower-priority zone issues aren't silently excluded.
                        r_wide = br(["ready", "--json", "--limit", "500"])
                        if r_wide.returncode == 0:
                            issues = json.loads(r_wide.stdout)
                        ready_ids = {i["id"] for i in issues}
                        r2 = br(["list", "--status=open", "--json", "--limit", "0"])
                        if r2.returncode == 0:
                            all_open = json.loads(r2.stdout)
                            labeled = {
                                i["id"]: i for i in all_open
                                if zone_labels.intersection(set(i.get("labels", [])))
                            }
                            issues = [
                                labeled[iid] for iid in ready_ids
                                if iid in labeled
                            ]
                    tasks = [i for i in issues if i.get("issue_type", "task") != "epic"]
                    pool = tasks if tasks else issues
                    candidates = [i["id"] for i in pool[:20]]
                except Exception:
                    pass

            if not candidates:
                log.log(f"No ready work found. Sleeping {DEV_SLEEP_NO_WORK}s...")
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                time.sleep(DEV_SLEEP_NO_WORK)
                continue

            for candidate in candidates:
                if issue_status_from_jsonl(candidate) == "in_progress":
                    log.log(f"Skipping candidate already in_progress in JSONL: {candidate}")
                    continue
                log.log(f"Selected task: {candidate}")
                if claim_task(candidate, agent_id, log, rename_prefix):
                    next_id = candidate
                    break

        if not next_id:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            log.log("Could not claim any ready task — retrying after backoff")
            time.sleep(random.randint(5, 25))
            continue

        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        log.log(f"Claimed {next_id}")

        # Build runtime prompt (base template + injected task context)
        dev_prompt = prompt_file.read_text()
        task_details = br(["show", next_id]).stdout.strip() or f"See issue ID: {next_id}"
        ready_output = br(["ready"]).stdout or ""
        ready_lines = "\n".join(ready_output.splitlines()[:15])
        in_progress = br(["list", "--status=in_progress"]).stdout.strip() or "None"

        # Build zone constraint block (injected only when zones are restricted)
        if zones:
            allowed_paths = []
            for z in zones:
                allowed_paths.extend(ZONES.get(z, [f"{z}/"]))
            paths_list = "\n".join(f"- `{p}`" for p in allowed_paths)
            zone_block = f"""
---

## Zone Constraint

You are operating in zone(s): {', '.join(f'`{z}`' for z in zones)}

**STRICT**: Only modify files inside:
{paths_list}

If you discover that work in another zone is required to complete this task, do NOT make
those changes yourself. Instead, create a beads issue for that work:
  `br create --title="..." --description="..." --type=task --priority=<N>`
Then add the appropriate zone label:
  `br update <new-id> --add-label zone:<zone>`
"""
        else:
            zone_block = ""

        runtime_prompt = f"""{dev_prompt}

---

## Your Current Task

**Issue ID**: `{next_id}`
**Agent**: `{agent_id}`

{task_details}
{zone_block}
---

## Current Beads State

### Ready to Work (unblocked, top 15)
{ready_lines}

### Currently In Progress
{in_progress}

---

**IMPORTANT**: This task has already been claimed by the loop script.
Do NOT run `br update {next_id} --status=in_progress` — it is already `in_progress`.
Start directly with understanding the task and implementing it.
"""

        log.log(f"Running {agent.title()} on task {next_id}...")
        exit_code, output = run_agent(agent, args.model, runtime_prompt, log)

        token_limit_hit = agent == "claude" and "Context limit reached" in output

        if exit_code != 0:
            log.log(f"WARNING: {agent.title()} exited with code {exit_code} for task {next_id}")
        else:
            log.log(f"{agent.title()} completed task {next_id}")

        # Extract and log the session summary if present
        summary = extract_session_summary(output)
        if summary:
            for line in summary:
                log.log(f"  {line}")
        else:
            # Fallback: log the last few non-empty lines of output
            tail = [l.strip() for l in output.splitlines() if l.strip()][-5:]
            if tail:
                log.log("  (no structured summary — last output lines:)")
                for line in tail:
                    log.log(f"  {line}")

        # Claude only: commit any uncommitted changes left by a token-limit interruption
        if agent == "claude":
            git(["add", "-A"])
            if git(["diff", "--cached", "--quiet"]).returncode != 0:
                log.log(f"WIP: committing uncommitted changes for {next_id}")
                r = git(["commit", "-m", f"wip: interrupted {next_id} [{agent_id}]", "--quiet"])
                if r.returncode == 0:
                    if git(["push", "--quiet"]).returncode == 0:
                        log.log("WIP: pushed")
                    else:
                        log.log("WARNING: WIP push failed")
                else:
                    log.log("WARNING: WIP commit failed — unstaging")
                    git(["restore", "--staged", "."])

        final_status = issue_status_from_jsonl(next_id)
        if final_status == "in_progress":
            log.log(
                f"Task {next_id} still in_progress after agent ran"
                f" — will resume on next iteration"
            )

        log.log("========================LOOP=========================")

        # Periodically clean up stale build artifacts (every DEV_CLEAN_EVERY iterations)
        if iteration % DEV_CLEAN_EVERY == 0:
            clean_build_artifacts(log)

        if token_limit_hit:
            log.log(f"Token limit hit — sleeping {DEV_SLEEP_TOKEN_LIMIT}s before next iteration")
            time.sleep(DEV_SLEEP_TOKEN_LIMIT)
        else:
            do_sleep(sleep_secs, jitter_secs, log)


# ── Review loops (qa, arch, quality, coverage) ─────────────────────────────────

def review_loop(args, log: Logger):
    loop_type = args.loop
    agent = args.agent

    prompt_file = SCRIPT_DIR / REVIEW_PROMPTS[loop_type]
    if not prompt_file.exists():
        log.log(f"ERROR: {prompt_file} not found. Exiting.")
        sys.exit(1)

    if args.sleep is not None:
        sleep_secs = args.sleep * 60
    else:
        sleep_secs = DEFAULT_SLEEP[loop_type]
    jitter_secs = args.jitter * 60

    max_iters = args.iterations
    iteration = 0
    per_run = loop_type in PER_RUN_LOG_LOOPS

    sleep_desc = f"{sleep_secs//60:.0f}m"
    if jitter_secs:
        sleep_desc += f" ±{jitter_secs//60:.0f}m jitter"

    log.banner([
        f"{agent.title()} {loop_type} loop starting",
        f"Prompt:   {prompt_file.name}",
        f"Log:      {log.log_file.name}",
        f"Sleep:    {sleep_desc}",
        f"Max runs: {'unlimited' if max_iters == 0 else max_iters}",
    ])

    while True:
        if stop_requested():
            log.log("STOP signal detected (.stop file exists). Exiting.")
            sys.exit(0)

        if max_iters > 0 and iteration >= max_iters:
            log.log(f"Reached max iterations ({max_iters}). Exiting.")
            sys.exit(0)

        label = f"{iteration + 1} of {max_iters}" if max_iters > 0 else str(iteration + 1)
        log.log(f"=== {loop_type.title()} review run {label} ===")

        git_pull_rebase(log)

        extra_log = None
        if per_run:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            extra_log = LOG_DIR / f"{agent}_{loop_type}_{ts}.log"
            log.log(f"Run log: {extra_log.name}")

        prompt_content = prompt_file.read_text()
        exit_code, _ = run_agent(agent, args.model, prompt_content, log, extra_log)

        if exit_code != 0:
            log.log(f"WARNING: {agent.title()} exited with code {exit_code}")
        else:
            log.log(f"{loop_type.title()} review completed successfully")

        # Clean up stale build artifacts after every review run — review loops run
        # cargo check/clippy/test which are the main contributors to target/debug growth.
        clean_build_artifacts(log)

        iteration += 1

        if stop_requested():
            log.log("STOP signal detected after review. Exiting.")
            sys.exit(0)

        if max_iters > 0 and iteration >= max_iters:
            log.log(f"Reached max iterations ({max_iters}). Exiting.")
            sys.exit(0)

        log.log("========================LOOP=========================")
        do_sleep(sleep_secs, jitter_secs, log)


# ── Argument parsing ───────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="loop.py",
        description="Unified agent loop runner for Red Cell C2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
loop types:
  dev       Development — claims beads tasks and implements them
  qa        QA review   — reviews recent commits, files issues (default sleep: 20m)
  arch      Architecture review — deep full-codebase analysis  (default sleep: 120m)
  quality   Test quality review — evaluates quality of existing tests (default sleep: 30m)
  coverage  Test coverage scan  — finds untested public functions    (default sleep: 30m)

examples:
  ./loop.py --agent claude --loop dev
  ./loop.py --agent claude --loop dev  --zone client-cli
  ./loop.py --agent codex  --loop dev  --zone teamserver
  ./loop.py --agent cursor --loop dev  --zone client-cli client
  ./loop.py --agent claude --loop dev  --sleep 0 --iterations 1
  ./loop.py --agent codex  --loop qa   --sleep 20
  ./loop.py --agent claude --loop arch --sleep 120 --jitter 15
  ./loop.py --agent cursor --loop coverage --sleep 30 --iterations 3
  ./loop.py --agent claude --loop dev  --pre-sleep 5 --model claude-opus-4-6
""",
    )
    parser.add_argument(
        "--agent",
        choices=["claude", "codex", "cursor"],
        default="claude",
        help="Agent to use (default: claude)",
    )
    parser.add_argument(
        "--loop",
        choices=["dev", "qa", "arch", "quality", "coverage"],
        default="dev",
        help="Loop type to run (default: dev)",
    )
    parser.add_argument(
        "--pre-sleep",
        type=float, default=0, metavar="MINUTES",
        help="Sleep N minutes before the first run (default: 0)",
    )
    parser.add_argument(
        "--sleep",
        type=float, default=None, metavar="MINUTES",
        help=(
            "Sleep N minutes after each iteration. "
            "If omitted, uses per-loop defaults: dev=0, qa=20, arch=120, quality/coverage=30"
        ),
    )
    parser.add_argument(
        "--jitter",
        type=float, default=0, metavar="MINUTES",
        help="Apply ±N minutes of random jitter to --sleep (default: 0)",
    )
    parser.add_argument(
        "--iterations",
        type=int, default=0, metavar="N",
        help="Max iterations before exit; 0 = run forever (default: 0)",
    )
    parser.add_argument(
        "--model",
        default=None, metavar="MODEL",
        help=(
            "Claude model to use (claude agent only). "
            "Example: claude-opus-4-6. Default: claude-sonnet-4-6"
        ),
    )
    parser.add_argument(
        "--zone",
        nargs="+",
        choices=list(ZONES.keys()),
        metavar="ZONE",
        help=(
            "Restrict dev loop to one or more zones: "
            + ", ".join(ZONES.keys())
            + ". Omit to work across all zones. "
            "Only applies to --loop dev. "
            "Example: --zone client-cli  or  --zone teamserver common"
        ),
    )
    parser.add_argument(
        "--stale-threshold",
        type=int, default=120, metavar="MINUTES",
        help=(
            "Minutes before a stuck in_progress task is auto-reset to open "
            "(dev loop only, default: 120)"
        ),
    )
    return parser.parse_args()


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if args.model and args.agent != "claude":
        print("ERROR: --model is only applicable with --agent claude", file=sys.stderr)
        sys.exit(1)

    log = Logger(
        agent_id=f"{socket.gethostname()}-{args.agent}",
        log_file=LOG_DIR / f"{args.agent}_{args.loop}.log",
    )

    if args.pre_sleep > 0:
        log.log(f"Pre-sleep: waiting {args.pre_sleep}m before first run...")
        time.sleep(args.pre_sleep * 60)

    if args.loop == "dev":
        dev_loop(args, log)
    else:
        review_loop(args, log)


if __name__ == "__main__":
    main()
