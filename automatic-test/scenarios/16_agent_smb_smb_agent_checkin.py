"""
Scenario 16_agent_smb: End-to-end agent checkin over SMB listener

**STATUS: ALWAYS SKIPPED** — direct SMB as a primary C2 channel is not
supported in the current architecture.  See "Architecture note" below.

Architecture note
-----------------
In the Demon protocol, SMB transport works as a **pivot relay**, not a direct
channel.  The Demon agent calls ``CreateNamedPipeW`` on the Windows target —
the *agent* is the pipe server.  A parent agent (already connected to the
teamserver over HTTP) connects to that pipe and relays traffic back.

On the teamserver side, the "SMB listener" (``listeners/smb.rs``) binds a
**local** IPC endpoint (Unix abstract socket on Linux, Windows named pipe on
Windows) via ``interprocess::local_socket``.  It is not a network-accessible
SMB/CIFS service and cannot be reached from a remote host.

Therefore, this scenario's premise — a remote Windows agent connecting
directly to a Linux teamserver's local pipe — is architecturally impossible.
The named pipe will never appear on the Windows target because the teamserver
creates it locally on Linux.

Scenario 10 (pivot dispatch) tests the correct architecture: HTTP parent →
SMB child pivot → teamserver relay.

If a "direct SMB" transport is ever implemented (e.g., teamserver connecting
outbound over network SMB to the agent's pipe), this scenario can be
re-enabled with the appropriate plumbing.  Until then it skips unconditionally.

See red-cell-c2-mnswy for the follow-up architecture issue.
"""

DESCRIPTION = "SMB agent checkin (Demon + Specter over SMB named pipe) [SKIP: arch]"

from lib import ScenarioSkipped


def run(ctx):
    """Always skips: direct SMB as primary C2 is not architecturally supported."""
    raise ScenarioSkipped(
        "Direct SMB as primary C2 is architecturally unsupported. "
        "The Demon agent creates a local Windows named pipe "
        "(CreateNamedPipeW) and waits for a parent agent to connect — "
        "the teamserver's SMB listener is a local IPC socket (Unix domain "
        "socket on Linux), not a network-accessible SMB service. "
        "Use scenario 10 (pivot dispatch) to test SMB transport. "
        "See red-cell-c2-mnswy for the follow-up architecture issue."
    )
