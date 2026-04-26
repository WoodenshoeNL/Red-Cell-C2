"""
Scenario 09_kerberos: Kerberos token ops

Tests Windows access-token and Kerberos ticket introspection via the
deployed Demon agent using native Windows shell commands.

When ``[kerberos]`` in ``config/env.toml`` has ``enabled = true`` (and
required fields), the harness validates structured ``klist`` and ``whoami /all``
output: ticket cache, client principal, expiry, impersonation level, and
expected domain group markers.

Skip conditions (``ScenarioSkipped`` with a clear message):

  - ``[kerberos]`` is missing, disabled, or empty
  - the Windows target is not domain-joined (``WORKGROUP`` / PartOfDomain false)
  - under strict Kerberos mode (``enabled = true``), ``klist`` failure is a
    hard error so the ticket cache cannot be validated

Strict Kerberos mode (``enabled = true``):

  1. Create + start HTTP listener
  2. Build Demon EXE (x64) for Windows target
  3. Deploy via SSH/SCP to Windows test machine
  4. Execute payload in background on target
  5. Wait for agent checkin
  6. ``whoami /all`` — assert TOKEN INFORMATION (impersonation level) and
     GROUP INFORMATION (expected domain group substrings)
  7. ``klist`` — assert at least one ticket for the configured principal with
     End Time in the future
  8. Network enumeration: ``netstat -ano``, ``arp -a``
  9. Kill agent, stop listener, clean up

Locale: section headers are expected in English (``whoami /all``, ``klist``).
"""

DESCRIPTION = "Kerberos token ops"

import uuid

from lib import ScenarioSkipped
from lib.config import KerberosSectionConfig, parse_env_config
from lib.deploy_agent import deploy_and_checkin
from lib.kerberos_checks import (
    assert_klist_ticket_cache,
    assert_whoami_token_and_groups,
)


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _kerberos_strict_config(ctx) -> KerberosSectionConfig:
    """Return parsed :class:`KerberosSectionConfig` or raise :class:`ScenarioSkipped`."""

    k = parse_env_config(ctx.env).kerberos
    if k is None or not k.enabled:
        raise ScenarioSkipped(
            "scenario 09 (Kerberos structured validation): configure [kerberos] in "
            "config/env.toml with enabled = true, domain_realm, account_name, and "
            "expected_groups (see comments in env.toml). Omit [kerberos] or set "
            "enabled = false to skip this scenario."
        )
    return k


def _windows_is_domain_joined(target) -> bool:
    """Return True if the host appears to be joined to an AD domain (not WORKGROUP)."""

    from lib.deploy import DeployError, run_remote

    try:
        out = run_remote(
            target,
            'powershell -NoProfile -Command "(Get-CimInstance Win32_ComputerSystem).PartOfDomain"',
            timeout=25,
        )
    except DeployError:
        out = ""
    else:
        s = out.strip().lower()
        if s == "true":
            return True
        if s == "false":
            return False
    try:
        out = run_remote(target, "wmic computersystem get domain /value", timeout=25)
    except DeployError:
        return False
    for line in out.splitlines():
        if line.strip().lower().startswith("domain="):
            dom = line.split("=", 1)[1].strip()
            return dom.upper() != "WORKGROUP"
    return False


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raises AssertionError with a descriptive message on any failure.
    Skips silently when ctx.windows is None.
    """
    if ctx.windows is None:
        raise ScenarioSkipped("ctx.windows is None — no Windows target configured")
    from lib.deploy import DeployError, preflight_ssh

    try:
        preflight_ssh(ctx.windows)
    except DeployError as exc:
        raise ScenarioSkipped(str(exc)) from exc

    kcfg = _kerberos_strict_config(ctx)
    if not _windows_is_domain_joined(ctx.windows):
        raise ScenarioSkipped(
            "scenario 09: Windows target does not appear to be domain-joined "
            "(PartOfDomain is false or Domain=WORKGROUP). Join the machine to AD "
            "or skip this scenario."
        )

    from lib.cli import (
        CliError,
        agent_exec,
        agent_kill,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
    )
    from lib.deploy import run_remote
    from lib.listeners import http_listener_kwargs

    cli = ctx.cli
    co = int(ctx.timeouts.command_output)
    target = ctx.windows
    uid = _short_id()
    listener_name = f"test-kerberos-{uid}"
    listener_port = ctx.env.get("listeners", {}).get("windows_port", 19082)

    # ── Step 1: Create + start HTTP listener ────────────────────────────────
    print(f"  [listener] creating HTTP listener {listener_name!r} on port {listener_port}")
    listener_create(cli, listener_name, "http", **http_listener_kwargs(listener_port, ctx.env, agent_type="demon"))
    listener_start(cli, listener_name)
    print("  [listener] started")

    agent_id = None
    try:
        # ── Steps 2-5: Build, deploy, exec, wait for checkin ─────────────────
        agent = deploy_and_checkin(
            ctx,
            cli,
            target,
            agent_type="demon",
            fmt="exe",
            listener_name=listener_name,
        )
        agent_id = agent["id"]

        # ── Step 6: List tokens via whoami /all ──────────────────────────────
        print("  [tokens] listing token info via 'whoami /all'")
        token_result = agent_exec(cli, agent_id, "whoami /all", wait=True, timeout=co)
        token_output = token_result.get("output", "").strip()

        assert token_output, "whoami /all returned empty output"
        assert_whoami_token_and_groups(
            token_output,
            expected_impersonation_level=kcfg.expected_impersonation_level,
            expected_group_substrings=kcfg.expected_groups,
        )
        print(
            f"  [tokens] TOKEN INFORMATION + GROUP INFORMATION validated "
            f"({len(token_output)} chars)"
        )

        # ── Step 7: Kerberos tickets via klist ───────────────────────────────
        print("  [kerberos] listing Kerberos tickets via 'klist'")
        try:
            klist_result = agent_exec(cli, agent_id, "klist", wait=True, timeout=co)
            klist_output = klist_result.get("output", "").strip()
        except CliError as exc:
            raise AssertionError(
                "klist failed under strict Kerberos mode — cannot validate ticket cache. "
                f"Underlying error: {exc}"
            ) from exc

        print(
            f"  [kerberos] klist output received ({len(klist_output)} chars): "
            f"{klist_output[:200]!r}"
        )
        assert klist_output, "klist returned empty output"
        assert (
            "LogonId" in klist_output
            or "Cached Tickets" in klist_output
            or "Ticket cache" in klist_output
        ), (
            "klist output does not contain expected Kerberos markers "
            "('LogonId', 'Cached Tickets', or 'Ticket cache').\n"
            f"  Output: {klist_output[:500]!r}"
        )
        assert_klist_ticket_cache(
            klist_output,
            kcfg.account_name,
            kcfg.domain_realm,
        )
        print("  [kerberos] ticket cache structure validated (principal + future expiry)")

        print("  [net] netstat -ano")
        netstat_result = agent_exec(cli, agent_id, "netstat -ano", wait=True, timeout=45)
        netstat_out = netstat_result.get("output", "").strip()
        assert netstat_out and ("TCP" in netstat_out or "UDP" in netstat_out), (
            f"netstat output missing protocol table: {netstat_out[:500]!r}"
        )
        print(f"  [net] netstat ok ({len(netstat_out)} chars)")

        print("  [net] arp -a")
        arp_result = agent_exec(cli, agent_id, "arp -a", wait=True, timeout=co)
        arp_out = arp_result.get("output", "").strip()
        assert arp_out, "arp -a returned empty output"
        assert (
            "Interface" in arp_out
            or "dynamic" in arp_out.lower()
            or "static" in arp_out.lower()
        ), f"arp output missing expected markers: {arp_out[:500]!r}"
        print(f"  [net] arp ok ({len(arp_out)} chars)")

        print("  [suite] all Kerberos token checks passed")

    finally:
        # ── Step 8: Kill agent, stop listener, clean up ──────────────────────
        if agent_id:
            print(f"  [cleanup] killing agent {agent_id}")
            try:
                agent_kill(cli, agent_id)
            except Exception as exc:
                print(f"  [cleanup] agent kill failed (non-fatal): {exc}")

        print(f"  [cleanup] stopping/deleting listener {listener_name!r}")
        try:
            listener_stop(cli, listener_name)
        except Exception:
            pass
        try:
            listener_delete(cli, listener_name)
        except Exception:
            pass

        print("  [cleanup] removing work_dir on target")
        try:
            run_remote(
                target,
                f'powershell -Command "Remove-Item -Recurse -Force -Path \'{target.work_dir}\'"',
                timeout=15,
            )
        except Exception as exc:
            print(f"  [cleanup] work_dir removal failed (non-fatal): {exc}")

        print("  [cleanup] done")
