"""
Scenario 12_rbac: RBAC enforcement

Verify role-based access control across all REST API endpoints.

Test steps:
  1. Skip when analyst_operator.api_key is absent/empty in env.toml
  2. Admin creates an analyst-role operator account (for parity with earlier tests)
  3. Admin creates an HTTP listener and builds a payload (blocking) for RBAC probes
  4. Analyst token: read-only operations (agent list, agent output, loot list, audit list)
     → allowed (exit 0; not auth failure for read-only)
  5. Analyst token: sensitive operations (listener start/stop/delete, payload build,
     payload download, agent kill, operator delete, operator set-role)
     → denied (exit code 3)
  6. Analyst token: listener create → denied (exit code 3)
  7. Analyst token: agent exec → denied (exit code 3)
  8. Analyst token: operator create → denied (exit code 3)
  9. Admin token: agent list → allowed
 10. Admin token: agent exec → not rejected for RBAC (may fail with agent-not-found)
 11. Admin token: operator create → allowed (new operator created and deleted)
 12. Cleanup: delete the viewer operator created in step 2, listeners, etc.

Skip condition:
  analyst_operator.api_key is absent or empty in config/env.toml
"""

DESCRIPTION = "RBAC enforcement"

import os
import tempfile
import uuid

from lib import ScenarioSkipped


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across runs."""
    return uuid.uuid4().hex[:8]


def _expect_rbac_denied(viewer_cfg, label: str, fn):
    """Assert viewer_cfg raises CliError with exit code 3 (auth / permission failure)."""
    from lib.cli import CliError

    try:
        fn()
        raise AssertionError(
            f"analyst-role token was NOT rejected for {label!r} — RBAC broken"
        )
    except CliError as exc:
        assert exc.exit_code == 3, (
            f"expected exit code 3 for analyst {label!r}, got {exc.exit_code}: {exc}"
        )


def run(ctx):
    """
    ctx.cli     — CliConfig (admin API key)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raises AssertionError with a descriptive message on any failure.
    Skips when no analyst API key is configured.
    """
    from lib.cli import (
        CliConfig,
        CliError,
        agent_exec,
        agent_kill,
        agent_list,
        agent_output,
        listener_create,
        listener_delete,
        listener_start,
        listener_stop,
        log_list,
        loot_list,
        operator_create,
        operator_delete,
        operator_set_role,
        payload_build,
        payload_download,
    )

    cli = ctx.cli
    env = ctx.env

    # ── Step 1: Skip when no analyst/viewer API key is configured ─────────────
    analyst_key = env.get("analyst_operator", {}).get("api_key", "")
    if not analyst_key:
        raise ScenarioSkipped(
            "RBAC enforcement test — "
            "set analyst_operator.api_key in config/env.toml to enable"
        )

    viewer_cfg = CliConfig(server=cli.server, token=analyst_key)
    uid = _short_id()
    viewer_username = f"test-viewer-{uid}"
    admin_test_listener = f"test-rbac-listener-{uid}"
    admin_test_operator = f"test-rbac-op-{uid}"

    # Track resources created during the test so cleanup always runs.
    viewer_created = False
    admin_listener_created = False
    admin_operator_created = False
    payload_id = None

    try:
        # ── Step 2: Admin creates a viewer-role operator ───────────────────────
        print(f"  [admin] creating analyst-role operator {viewer_username!r}")
        result = operator_create(cli, viewer_username, "viewer-pass-" + uid, "analyst")
        assert result.get("username") == viewer_username, (
            f"operator create returned unexpected username: {result.get('username')!r}"
        )
        assert result.get("role") == "analyst", (
            f"operator create returned unexpected role: {result.get('role')!r}"
        )
        viewer_created = True
        print(f"  [admin] viewer operator created: role={result.get('role')!r}")

        # ── Step 3: Admin listener + payload so analyst can probe download/delete ─
        print(f"  [admin] listener create {admin_test_listener!r} → should be allowed")
        rbac_admin_port = ctx.env.get("listeners", {}).get("rbac_admin_port", 19098)
        listener_create(cli, admin_test_listener, "http", port=rbac_admin_port)
        admin_listener_created = True
        print("  [admin] listener create allowed ✓")

        print("  [admin] payload build (wait) → artifact for analyst download probe")
        try:
            built = payload_build(
                cli,
                listener=admin_test_listener,
                arch="x64",
                fmt="exe",
                agent="demon",
                wait=True,
            )
            payload_id = built.get("id")
            assert payload_id, f"payload build did not return id: {built!r}"
        except Exception as exc:
            raise AssertionError(
                f"admin payload build failed — cannot test analyst payload download: {exc}"
            ) from exc
        print(f"  [admin] payload built id={payload_id!r} ✓")

        # ── Step 4: Analyst token — read-only allowed ───────────────────────────
        print("  [analyst] agent list → should be allowed")
        agents = agent_list(viewer_cfg)
        assert isinstance(agents, list), (
            f"analyst agent list did not return a list: {agents!r}"
        )
        print(f"  [analyst] agent list allowed ({len(agents)} agents) ✓")

        print("  [analyst] agent output → should be allowed (read-only)")
        if agents:
            aid = str(agents[0].get("id", "")).strip()
            if aid:
                agent_output(viewer_cfg, aid)
                print(f"  [analyst] agent output allowed (agent {aid!r}) ✓")
            else:
                print("  [analyst] agent list entry missing id — skipping agent output probe")
        else:
            try:
                agent_output(viewer_cfg, "00000000-0000-0000-0000-000000000001")
            except CliError as exc:
                assert exc.exit_code != 3, (
                    f"analyst was RBAC-blocked for agent output (exit 3): {exc}"
                )
        print("  [analyst] agent output probe done ✓")

        print("  [analyst] loot list → should be allowed")
        loot_rows = loot_list(viewer_cfg)
        assert isinstance(loot_rows, list), (
            f"analyst loot list did not return a list: {loot_rows!r}"
        )
        print(f"  [analyst] loot list allowed ({len(loot_rows)} rows) ✓")

        print("  [analyst] audit log list (CLI log list) → should be allowed")
        audit_rows = log_list(viewer_cfg)
        assert isinstance(audit_rows, list), (
            f"analyst log list did not return a list: {audit_rows!r}"
        )
        print(f"  [analyst] log list allowed ({len(audit_rows)} rows) ✓")

        # ── Step 5: Analyst token — sensitive operations denied (exit 3) ────────
        print("  [analyst] listener start → should be denied (exit code 3)")
        _expect_rbac_denied(
            viewer_cfg,
            "listener start",
            lambda: listener_start(viewer_cfg, admin_test_listener),
        )
        print("  [analyst] listener start denied (exit 3) ✓")

        print("  [analyst] listener stop → should be denied (exit code 3)")
        _expect_rbac_denied(
            viewer_cfg,
            "listener stop",
            lambda: listener_stop(viewer_cfg, admin_test_listener),
        )
        print("  [analyst] listener stop denied (exit 3) ✓")

        print("  [analyst] listener delete → should be denied (exit code 3)")
        _expect_rbac_denied(
            viewer_cfg,
            "listener delete",
            lambda: listener_delete(viewer_cfg, admin_test_listener),
        )
        print("  [analyst] listener delete denied (exit 3) ✓")

        print("  [analyst] payload build → should be denied (exit code 3)")
        _expect_rbac_denied(
            viewer_cfg,
            "payload build",
            lambda: payload_build(
                viewer_cfg,
                listener=admin_test_listener,
                arch="x64",
                fmt="exe",
                agent="demon",
                wait=False,
            ),
        )
        print("  [analyst] payload build denied (exit 3) ✓")

        # Download requires a real payload id (admin-only build above).
        fd, tmp_path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        try:
            print("  [analyst] payload download → should be denied (exit code 3)")
            _expect_rbac_denied(
                viewer_cfg,
                "payload download",
                lambda: payload_download(viewer_cfg, str(payload_id), tmp_path),
            )
            print("  [analyst] payload download denied (exit 3) ✓")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        print("  [analyst] agent kill → should be denied (exit code 3)")
        _expect_rbac_denied(
            viewer_cfg,
            "agent kill",
            lambda: agent_kill(
                viewer_cfg,
                "00000000-0000-0000-0000-000000000000",
            ),
        )
        print("  [analyst] agent kill denied (exit 3) ✓")

        print("  [analyst] operator delete → should be denied (exit code 3)")
        _expect_rbac_denied(
            viewer_cfg,
            "operator delete",
            lambda: operator_delete(viewer_cfg, viewer_username),
        )
        print("  [analyst] operator delete denied (exit 3) ✓")

        print("  [analyst] operator set-role → should be denied (exit code 3)")
        _expect_rbac_denied(
            viewer_cfg,
            "operator set-role",
            lambda: operator_set_role(viewer_cfg, viewer_username, "admin"),
        )
        print("  [analyst] operator set-role denied (exit 3) ✓")

        # ── Step 6–8: Analyst listener create / exec / operator create ─────────
        print("  [analyst] listener create → should be denied (exit code 3)")
        try:
            rbac_viewer_port = ctx.env.get("listeners", {}).get("rbac_viewer_port", 19099)
            listener_create(viewer_cfg, f"rbac-probe-{uid}", "http", port=rbac_viewer_port)
            raise AssertionError(
                "analyst-role token was NOT rejected for 'listener create' — RBAC broken"
            )
        except CliError as exc:
            assert exc.exit_code == 3, (
                f"expected exit code 3 for analyst 'listener create', got {exc.exit_code}: {exc}"
            )
        print("  [analyst] listener create denied (exit 3) ✓")

        print("  [analyst] agent exec → should be denied (exit code 3)")
        try:
            agent_exec(viewer_cfg, "00000000-0000-0000-0000-000000000000", "whoami")
            raise AssertionError(
                "analyst-role token was NOT rejected for 'agent exec' — RBAC broken"
            )
        except CliError as exc:
            assert exc.exit_code == 3, (
                f"expected exit code 3 for analyst 'agent exec', got {exc.exit_code}: {exc}"
            )
        print("  [analyst] agent exec denied (exit 3) ✓")

        print("  [analyst] operator create → should be denied (exit code 3)")
        try:
            operator_create(
                viewer_cfg,
                username=f"_rbac-probe-{uid}_",
                password="probe-pass",
                role="analyst",
            )
            raise AssertionError(
                "analyst-role token was NOT rejected for 'operator create' — RBAC broken"
            )
        except CliError as exc:
            assert exc.exit_code == 3, (
                f"expected exit code 3 for analyst 'operator create', got {exc.exit_code}: {exc}"
            )
        print("  [analyst] operator create denied (exit 3) ✓")

        # ── Step 9–11: Admin token — positive paths ──────────────────────────────
        print("  [admin] agent list → should be allowed")
        agents = agent_list(cli)
        assert isinstance(agents, list), (
            f"admin agent list did not return a list: {agents!r}"
        )
        print(f"  [admin] agent list allowed ({len(agents)} agents) ✓")

        print("  [admin] agent exec on dummy id → should not be RBAC-rejected")
        try:
            agent_exec(cli, "00000000-0000-0000-0000-000000000000", "whoami")
        except CliError as exc:
            assert exc.exit_code != 3, (
                f"admin was RBAC-rejected for 'agent exec' (exit 3) — RBAC broken: {exc}"
            )
            print(f"  [admin] agent exec failed as expected (non-RBAC, exit {exc.exit_code})")
        print("  [admin] agent exec not RBAC-rejected ✓")

        print(f"  [admin] operator create {admin_test_operator!r} → should be allowed")
        result = operator_create(cli, admin_test_operator, "temp-pass-" + uid, "analyst")
        assert result.get("username") == admin_test_operator, (
            f"admin operator create returned unexpected username: {result.get('username')!r}"
        )
        admin_operator_created = True
        print("  [admin] operator create allowed ✓")

        print("  [suite] all RBAC checks passed")

    finally:
        # ── Step 12: Cleanup ───────────────────────────────────────────────────
        if admin_operator_created:
            print(f"  [cleanup] deleting admin-created test operator {admin_test_operator!r}")
            try:
                operator_delete(cli, admin_test_operator)
            except Exception as exc:
                print(f"  [cleanup] admin test operator delete failed (non-fatal): {exc}")

        if admin_listener_created:
            print(f"  [cleanup] deleting admin-created test listener {admin_test_listener!r}")
            try:
                listener_delete(cli, admin_test_listener)
            except Exception as exc:
                print(f"  [cleanup] admin test listener delete failed (non-fatal): {exc}")

        if viewer_created:
            print(f"  [cleanup] deleting viewer operator {viewer_username!r}")
            try:
                operator_delete(cli, viewer_username)
            except Exception as exc:
                print(f"  [cleanup] viewer operator delete failed (non-fatal): {exc}")

        print("  [cleanup] done")
