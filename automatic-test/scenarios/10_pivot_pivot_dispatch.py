"""
Scenario 10_pivot: Pivot chain dispatch

Tests a two-hop pivot chain where Agent A (pivot parent, directly connected
to the C2 server) relays traffic for Agent B (pivot child, connected to the
C2 server only through Agent A's internal SMB named-pipe listener).

Test steps (full path):
  1. Create + start HTTP listener for the parent agent
  2. Build Demon EXE for host 1 (parent)
  3. Deploy + execute on host 1; wait for parent agent checkin
  4. Open an SMB pivot pipe on the parent agent
     (red-cell-cli agent exec <id> --cmd "pivot smb connect <pipe>")
  5. Build a second Demon EXE linked to the SMB pivot listener
  6. Deploy + execute on host 2 (same or different machine)
  7. Wait for child agent checkin through the pivot
  8. Send `whoami` through the child agent; verify output is non-empty
  9. Verify agent topology: child's parent_id == parent agent ID
 10. Disconnect pivot (pivot smb disconnect <child-id>)
 11. Verify child agent transitions to inactive / unreachable
 12. Cleanup: kill parent agent, stop + delete HTTP listener

Demon pivot implementation details (from src/Havoc/teamserver/pkg/agent/demons.go):
  COMMAND_PIVOT / DEMON_PIVOT_SMB_CONNECT  = 2520 / 10
  DEMON_PIVOT_SMB_DISCONNECT               = 2520 / 11
  DEMON_PIVOT_SMB_COMMAND                  = 2520 / 12

Skip conditions (applied in order — first match wins):
  A. Fewer than two target machines available.
  B. Only one Windows target — SMB pivot (Demon) requires Windows named pipes;
     this test cannot run with a single Windows host.
  C. Linux-only targets — Demon pivot uses Windows SMB; a TCP/bind pivot for
     Linux would require the Phantom agent which is not yet implemented.
  D. Mixed Linux + Windows — a Linux-hosted TCP pivot relay would need Phantom;
     cross-platform SMB is not supported by Demon.

When any skip condition is met the test prints the reason and returns without
raising an exception, so the overall test suite still passes.
"""

DESCRIPTION = "Pivot chain dispatch"

import uuid

from lib import ScenarioSkipped


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across runs."""
    return uuid.uuid4().hex[:8]


# ── Skip-condition messages ──────────────────────────────────────────────────

_SKIP_ONE_TARGET = (
    "pivot chain requires two active agents on two separate hosts; "
    "only one (or zero) targets are configured"
)
_SKIP_MIXED_TARGETS = (
    "one Linux + one Windows target configured — "
    "SMB pivot requires two Windows hosts (Demon uses Windows named pipes); "
    "TCP/bind pivot from a Linux host requires the Phantom Linux agent "
    "which is not yet implemented — skipping until Phantom is available "
    "or a second Windows target is added to targets.toml"
)
_SKIP_LINUX_ONLY = (
    "only Linux targets available — Demon SMB pivot requires Windows; "
    "TCP pivot via Phantom Linux agent is not yet implemented"
)


def run(ctx):
    """
    Pivot chain dispatch scenario.

    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raises AssertionError with a descriptive message on any failure.
    Prints a skip notice and returns cleanly when conditions are not met.
    """

    # ── A. Require at least two targets ─────────────────────────────────────
    target_count = sum(1 for t in (ctx.linux, ctx.windows) if t is not None)
    if target_count < 2:
        raise ScenarioSkipped(_SKIP_ONE_TARGET)

    # ── B/C/D. Mixed or Linux-only: Phantom not yet available ───────────────
    # A proper SMB pivot chain requires two Windows hosts.
    # A TCP pivot chain requires the Phantom Linux agent (not yet implemented).
    if ctx.linux is not None and ctx.windows is None:
        raise ScenarioSkipped(_SKIP_LINUX_ONLY)

    if ctx.linux is not None and ctx.windows is not None:
        # Mixed pair: would need Phantom for a Linux parent node.
        _print_future_plan()
        raise ScenarioSkipped(_SKIP_MIXED_TARGETS)

    # If we somehow reach here with two Windows targets (ctx.windows is
    # non-None but no Linux) we would execute the full SMB pivot test.
    # That path is unreachable with the current single-[windows] harness
    # config but is left as the implementation target for when a second
    # Windows machine is added.
    #
    # NOTE: remove this guard and wire up ctx.windows2 in test.py when
    # a second Windows target is available.
    _print_future_plan()
    raise ScenarioSkipped(
        "two-Windows pivot path not yet reachable — "
        "harness config supports only one [windows] target; "
        "add ctx.windows2 to RunContext and targets.toml to enable"
    )


def _print_future_plan():
    """Print the full two-hop SMB pivot test plan for future implementers."""
    print()
    print("  Pivot chain test plan (activate when two Windows targets are available):")
    print("  ┌─────────────────────────────────────────────────────────────────────┐")
    print("  │ Prerequisites:                                                      │")
    print("  │   • ctx.windows  — Windows host 1 (pivot parent)                  │")
    print("  │   • ctx.windows2 — Windows host 2 (pivot child)                   │")
    print("  │   Both hosts must be able to reach each other over SMB (TCP 445). │")
    print("  │                                                                     │")
    print("  │ Step 1  Create + start HTTP listener (for parent direct callback). │")
    print("  │ Step 2  Build Demon EXE (x64) linked to HTTP listener.             │")
    print("  │ Step 3  Deploy + exec on host 1; poll agent_list for new checkin.  │")
    print("  │ Step 4  agent exec <parent_id> --cmd 'pivot smb connect \\\\.\\pipe\\<name>' │")
    print("  │         to start the SMB relay pipe on the parent agent.           │")
    print("  │ Step 5  Poll listener_list until the SMB pivot listener appears.   │")
    print("  │ Step 6  Build Demon EXE linked to the SMB pivot listener.          │")
    print("  │ Step 7  Deploy + exec on host 2; poll agent_list for child agent.  │")
    print("  │ Step 8  Verify child agent shows parent_id == parent agent ID.     │")
    print("  │ Step 9  agent exec <child_id> --cmd 'whoami'; verify output.       │")
    print("  │ Step 10 agent exec <parent_id> --cmd 'pivot smb disconnect <child_id>' │")
    print("  │ Step 11 Poll agent_list; verify child transitions to inactive.     │")
    print("  │ Step 12 Cleanup: kill parent, stop + delete HTTP listener,         │")
    print("  │         remove payload files from both hosts.                      │")
    print("  └─────────────────────────────────────────────────────────────────────┘")
