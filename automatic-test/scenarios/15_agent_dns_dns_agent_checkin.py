"""
Scenario 15_agent_dns: End-to-end agent checkin over DNS listener

Placeholder for future DNS-as-primary-transport agent support.  Currently
unconditionally SKIPPED: no agent in the project implements DNS as a primary
C2 transport.

Transport matrix (as of 2026-04):

  Demon    — HTTP, SMB                 (upstream Havoc: no TransportDns)
  Phantom  — HTTP only                 (agent/phantom/src/agent/transport.rs)
  Specter  — HTTP + DoH fallback       (agent/specter/src/doh_transport.rs,
                                        via public cloudflare/google resolvers)
  Archon   — HTTP + DoH fallback       (agent/archon/src/core/TransportDoH.c,
                                        via public cloudflare/google resolvers)

DoH is a fallback that tunnels through public DoH resolvers — it does not talk
directly to our DNS listener.  The teamserver payload builder reflects this by
rejecting DNS listeners for Rust agent builds
(teamserver/src/payload_builder/rust_agent.rs: "{} listeners are not supported
for Rust agent payload builds").

DoH + DNS listener interop is covered by scenario 20
(``20_agent_doh_dns_listener_interop.py``) via raw wire-format probes plus an
optional Specter-with-DoH-fallback agent pass.

When a Rust agent gains primary-DNS transport support:
  1. Remove the ``ScenarioSkipped`` raise in :func:`run`.
  2. Remove the DNS-listener exclusion in
     ``teamserver/src/payload_builder/rust_agent.rs`` and wire the DNS build
     flags through ``rust_agent_callback_url``.
  3. The existing :func:`_run_for_agent` body below is the test template —
     create + start DNS listener, build payload, deploy, checkin, command
     suite, cleanup.
"""

DESCRIPTION = "DNS agent checkin (SKIPPED — no Rust agent has primary-DNS transport)"

import uuid

from lib import ScenarioSkipped


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _run_for_agent(ctx, agent_type: str, fmt: str, name_prefix: str) -> None:
    """Run the full DNS checkin suite for one agent type.

    Args:
        ctx:         RunContext passed by the harness.
        agent_type:  Agent name passed to ``payload_build`` (e.g. ``"demon"``
                     or ``"phantom"``).
        fmt:         Payload format (``"exe"`` is required for Rust agents like Phantom).
        name_prefix: Short prefix used to name the listener and remote files.

    Raises:
        AssertionError on test failure.
        CliError if the payload build fails (propagates as a scenario failure).
    """
    from lib.cli import (
        agent_exec,
        agent_kill,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
    )
    from lib.deploy import run_remote
    from lib.deploy_agent import deploy_and_checkin

    cli = ctx.cli
    co = int(ctx.timeouts.command_output)
    target = ctx.linux
    uid = _short_id()
    listener_name = f"{name_prefix}-{uid}"

    dns_cfg = ctx.env.get("listeners", {})
    dns_port = dns_cfg.get("dns_port", 15353)
    dns_domain = dns_cfg.get("dns_domain", "c2.test.local")

    # ── Step 1: Create + start DNS listener ─────────────────────────────────
    print(
        f"  [{agent_type}][listener] creating DNS listener {listener_name!r} "
        f"on port {dns_port}, domain {dns_domain!r}"
    )
    listener_create(
        cli, listener_name, "dns",
        port=dns_port,
        domain=dns_domain,
    )
    listener_start(cli, listener_name)
    print(f"  [{agent_type}][listener] started")

    agent_id = None
    try:
        # ── Steps 2-5: Build, deploy, exec, wait for checkin ─────────────────
        agent = deploy_and_checkin(
            ctx, cli, target,
            agent_type=agent_type, fmt=fmt,
            listener_name=listener_name,
            label=agent_type,
        )
        agent_id = agent["id"]

        # ── Step 6: Command suite ────────────────────────────────────────────

        # whoami → contains the expected SSH username
        print(f"  [{agent_type}][cmd] whoami")
        result = agent_exec(cli, agent_id, "whoami", wait=True, timeout=co)
        whoami_out = result.get("output", "").strip()
        assert whoami_out, "whoami returned empty output"
        assert target.user in whoami_out, (
            f"whoami output {whoami_out!r} does not contain "
            f"expected user {target.user!r}"
        )
        print(f"  [{agent_type}][cmd] whoami passed: {whoami_out!r}")

        # pwd → returns an absolute path
        print(f"  [{agent_type}][cmd] pwd")
        result = agent_exec(cli, agent_id, "pwd", wait=True, timeout=co)
        pwd_out = result.get("output", "").strip()
        assert pwd_out, "pwd returned empty output"
        assert pwd_out.startswith("/"), (
            f"pwd output is not an absolute path: {pwd_out!r}"
        )
        print(f"  [{agent_type}][cmd] pwd passed: {pwd_out!r}")

        # ls / → non-empty directory listing
        print(f"  [{agent_type}][cmd] ls /")
        result = agent_exec(cli, agent_id, "ls /", wait=True, timeout=co)
        ls_out = result.get("output", "").strip()
        assert ls_out, "ls / returned empty output"
        print(f"  [{agent_type}][cmd] ls / passed ({len(ls_out.splitlines())} entries)")

        # hostname → matches the hostname reported by SSH
        print(f"  [{agent_type}][cmd] hostname")
        expected_hostname = run_remote(target, "hostname").strip()
        result = agent_exec(cli, agent_id, "hostname", wait=True, timeout=co)
        hostname_out = result.get("output", "").strip()
        assert hostname_out, "hostname returned empty output"
        assert hostname_out == expected_hostname, (
            f"hostname mismatch: agent reported {hostname_out!r}, "
            f"SSH reports {expected_hostname!r}"
        )
        print(f"  [{agent_type}][cmd] hostname passed: {hostname_out!r}")

        print(f"  [{agent_type}][suite] all DNS commands passed")

    finally:
        # ── Step 7: Kill agent, stop listener, clean up ──────────────────────
        if agent_id:
            print(f"  [{agent_type}][cleanup] killing agent {agent_id}")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [{agent_type}][cleanup] agent kill failed (non-fatal): {exc}")

        print(f"  [{agent_type}][cleanup] stopping/deleting DNS listener {listener_name!r}")
        try:
            listener_stop(cli, listener_name)
        except Exception:
            pass
        try:
            listener_delete(cli, listener_name)
        except Exception:
            pass

        print(f"  [{agent_type}][cleanup] removing work_dir on target")
        try:
            run_remote(target, f"rm -rf {target.work_dir}", timeout=15)
        except Exception as exc:
            print(f"  [{agent_type}][cleanup] work_dir removal failed (non-fatal): {exc}")

        print(f"  [{agent_type}][cleanup] done")


def run(ctx):
    """
    Always raises :class:`ScenarioSkipped`.

    See the module docstring for why: no project agent implements DNS as a
    primary C2 transport, and the teamserver's Rust-agent payload builder
    explicitly rejects DNS listeners.  DoH fallback interop is covered by
    scenario 20.
    """
    raise ScenarioSkipped(
        "no agent implements DNS as a primary C2 transport — Phantom is "
        "HTTP-only; Specter/Archon DoH is a public-resolver fallback, not "
        "direct DNS-listener transport; teamserver rust_agent.rs rejects "
        "DNS listeners for Rust builds. See scenario 20 for DoH+DNS "
        "listener interop coverage."
    )
