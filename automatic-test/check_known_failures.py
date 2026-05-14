#!/usr/bin/env python3
"""
check_known_failures.py — validate KNOWN_FAILURES.md Active table before autotest.

Parses the Active section, checks each referenced bead via `br show`, and
reports any closed beads as stale entries.  A stale entry causes the autotest
agent to misclassify failures as "known / skip investigation" when the bead is
actually closed and no one is working it.

Exit codes:
  0 — all Active beads are open or in_progress (or Active table is empty)
  1 — one or more Active beads are CLOSED, NOT_FOUND, or UNKNOWN — fix KNOWN_FAILURES.md first
  2 — `br` not found, KNOWN_FAILURES.md missing, or other execution error
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

KNOWN_FAILURES = Path(__file__).resolve().parent / "KNOWN_FAILURES.md"
# Matches a cell whose entire trimmed content is a single bead ID (not "*(fixed inline)*" etc.)
_BEAD_CELL_RE = re.compile(r"^red-cell-c2-[a-z0-9]+$")


def _parse_active_beads(text: str) -> list[str]:
    """Return deduplicated bead IDs from the Bead column of the Active table.

    Only column 3 (| Signature | Scenario | Bead | …) is examined.  Bead IDs
    that appear anywhere else in the section — e.g. in Signature text as
    predecessor references — are intentionally ignored so they cannot
    cause false-positive stale-bead failures.
    """
    m = re.search(r"^## Active\s*\n(.+?)^---", text, re.MULTILINE | re.DOTALL)
    if not m:
        return []
    bead_ids: list[str] = []
    for line in m.group(1).splitlines():
        parts = line.split("|")
        # Pipe-delimited table rows produce at least 5 parts:
        # ["", sig, scenario, bead, ...]
        if len(parts) < 5:
            continue
        bead_cell = parts[3].strip()
        if _BEAD_CELL_RE.match(bead_cell):
            bead_ids.append(bead_cell)
    return list(dict.fromkeys(bead_ids))


def _check_bead(bead_id: str) -> tuple[str, str]:
    """Return (status, title) by running `br show <id>`.

    Status is one of OPEN, IN_PROGRESS, CLOSED, NOT_FOUND, UNKNOWN.
    NOT_FOUND means `br show` returned a non-zero exit code — the bead ID
    does not exist in the database (likely a typo in KNOWN_FAILURES.md).
    """
    try:
        result = subprocess.run(
            ["br", "show", bead_id],
            capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError:
        print(
            "ERROR: `br` command not found — cannot validate bead statuses.\n"
            "Install beads_rust or add it to PATH.",
            file=sys.stderr,
        )
        sys.exit(2)
    except subprocess.TimeoutExpired:
        return "UNKNOWN", "(br show timed out)"

    if result.returncode != 0:
        return "NOT_FOUND", "(bead not in database)"

    out = result.stdout
    sm = re.search(r"\b(OPEN|IN_PROGRESS|CLOSED)\b", out)
    status = sm.group(1) if sm else "UNKNOWN"
    # Title sits between the bead ID marker and the status badge, e.g.:
    # "◐ red-cell-c2-qqi66 · bug title   [● P1 · OPEN]"
    tm = re.search(rf"{re.escape(bead_id)}\s*[·:]\s*(.+?)\s+\[", out)
    title = tm.group(1).strip() if tm else "(title unavailable)"
    return status, title


def main() -> int:
    if not KNOWN_FAILURES.exists():
        print(f"ERROR: {KNOWN_FAILURES} not found", file=sys.stderr)
        return 2

    text = KNOWN_FAILURES.read_text()
    bead_ids = _parse_active_beads(text)

    if not bead_ids:
        print("check_known_failures: Active table is empty — nothing to validate.")
        return 0

    print(f"check_known_failures: validating {len(bead_ids)} bead(s) in Active table...")
    stale: list[tuple[str, str, str]] = []  # (bead_id, status, title)

    for bead_id in bead_ids:
        status, title = _check_bead(bead_id)
        mark = "✓" if status in ("OPEN", "IN_PROGRESS") else "✗"
        print(f"  {mark} {bead_id} [{status}]  {title}")
        if status not in ("OPEN", "IN_PROGRESS"):
            stale.append((bead_id, status, title))

    if stale:
        print(
            f"\ncheck_known_failures: {len(stale)} STALE entry/entries in Active table.\n"
            "\nEach stale entry causes failures to be silently misclassified as\n"
            "'known / skip investigation' even though no one is working the fix.\n"
            "\nFix KNOWN_FAILURES.md before classifying failures:\n"
        )
        for bead_id, status, title in stale:
            if status == "NOT_FOUND":
                print(f"  • {bead_id} [NOT_FOUND] — bead ID not in database (typo?)")
                print(f"    Fix the bead ID in KNOWN_FAILURES.md Active table.")
            elif status == "UNKNOWN":
                print(f"  • {bead_id} [UNKNOWN] — br show timed out; check manually before removing")
            else:
                print(f"  • {bead_id} is CLOSED — move its row to the Resolved section")
                print(f"    and add a new Active row pointing to the replacement bead,")
                print(f"    or remove it if the failure is genuinely no longer occurring.")
        return 1

    print("check_known_failures: Active table is clean — all beads are open or in_progress.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
