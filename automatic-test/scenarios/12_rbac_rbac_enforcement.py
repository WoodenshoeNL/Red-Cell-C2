"""
Scenario 12_rbac: RBAC enforcement

Verify role-based access control across all REST API endpoints.

Test steps:
  1. Skip when analyst_operator.api_key is absent/empty in env.toml
  2. Admin creates a viewer-role (analyst) operator account
     → verifies that admin is permitted to call operator create
  3. Viewer token: agent list → allowed (exit 0)
  4. Viewer token: listener create → denied (exit code 3)
  5. Viewer token: agent exec → denied (exit code 3)
  6. Viewer token: operator create → denied (exit code 3)
  7. Admin token: agent list → allowed
  8. Admin token: listener create → allowed (listener created and deleted)
  9. Admin token: agent exec → not rejected for RBAC (may fail with agent-not-found)
 10. Admin token: operator create → allowed (new operator created and deleted)
 11. Cleanup: delete the viewer operator created in step 2

Skip condition:
  analyst_operator.api_key is absent or empty in config/env.toml
"""

DESCRIPTION = "RBAC enforcement"

import uuid


def _short_id() -> str:
    """Return a short unique hex suffix to avoid name collisions across runs."""
    return uuid.uuid4().hex[:8]


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
        agent_list,
        listener_create,
        listener_delete,
        operator_create,
        operator_delete,
    )

    cli = ctx.cli
    env = ctx.env

    # ── Step 1: Skip when no analyst/viewer API key is configured ─────────────
    analyst_key = env.get("analyst_operator", {}).get("api_key", "")
    if not analyst_key:
        print(
            "  [skip] RBAC enforcement test — "
            "set analyst_operator.api_key in config/env.toml to enable"
        )
        return

    viewer_cfg = CliConfig(server=cli.server, token=analyst_key)
    uid = _short_id()
    viewer_username = f"test-viewer-{uid}"
    admin_test_listener = f"test-rbac-listener-{uid}"
    admin_test_operator = f"test-rbac-op-{uid}"

    # Track resources created during the test so cleanup always runs.
    viewer_created = False
    admin_listener_created = False
    admin_operator_created = False

    try:
        # ── Step 2: Admin creates a viewer-role operator ───────────────────────
        print(f"  [admin] creating viewer-role operator {viewer_username!r}")
        result = operator_create(cli, viewer_username, "viewer-pass-" + uid, "analyst")
        assert result.get("username") == viewer_username, (
            f"operator create returned unexpected username: {result.get('username')!r}"
        )
        assert result.get("role") == "analyst", (
            f"operator create returned unexpected role: {result.get('role')!r}"
        )
        viewer_created = True
        print(f"  [admin] viewer operator created: role={result.get('role')!r}")

        # ── Step 3: Viewer token → agent list (allowed) ────────────────────────
        print("  [viewer] agent list → should be allowed")
        agents = agent_list(viewer_cfg)
        assert isinstance(agents, list), (
            f"viewer agent list did not return a list: {agents!r}"
        )
        print(f"  [viewer] agent list allowed ({len(agents)} agents) ✓")

        # ── Step 4: Viewer token → listener create (denied, exit code 3) ──────
        print("  [viewer] listener create → should be denied (exit code 3)")
        try:
            listener_create(viewer_cfg, f"rbac-probe-{uid}", "http", port=19099)
            raise AssertionError(
                "viewer-role token was NOT rejected for 'listener create' — RBAC broken"
            )
        except CliError as exc:
            assert exc.exit_code == 3, (
                f"expected exit code 3 for viewer 'listener create', got {exc.exit_code}: {exc}"
            )
        print("  [viewer] listener create denied (exit 3) ✓")

        # ── Step 5: Viewer token → agent exec (denied, exit code 3) ──────────
        print("  [viewer] agent exec → should be denied (exit code 3)")
        try:
            agent_exec(viewer_cfg, "00000000-0000-0000-0000-000000000000", "whoami")
            raise AssertionError(
                "viewer-role token was NOT rejected for 'agent exec' — RBAC broken"
            )
        except CliError as exc:
            assert exc.exit_code == 3, (
                f"expected exit code 3 for viewer 'agent exec', got {exc.exit_code}: {exc}"
            )
        print("  [viewer] agent exec denied (exit 3) ✓")

        # ── Step 6: Viewer token → operator create (denied, exit code 3) ─────
        print("  [viewer] operator create → should be denied (exit code 3)")
        try:
            operator_create(
                viewer_cfg,
                username=f"_rbac-probe-{uid}_",
                password="probe-pass",
                role="analyst",
            )
            raise AssertionError(
                "viewer-role token was NOT rejected for 'operator create' — RBAC broken"
            )
        except CliError as exc:
            assert exc.exit_code == 3, (
                f"expected exit code 3 for viewer 'operator create', got {exc.exit_code}: {exc}"
            )
        print("  [viewer] operator create denied (exit 3) ✓")

        # ── Step 7: Admin token → agent list (allowed) ────────────────────────
        print("  [admin] agent list → should be allowed")
        agents = agent_list(cli)
        assert isinstance(agents, list), (
            f"admin agent list did not return a list: {agents!r}"
        )
        print(f"  [admin] agent list allowed ({len(agents)} agents) ✓")

        # ── Step 8: Admin token → listener create (allowed) ───────────────────
        print(f"  [admin] listener create {admin_test_listener!r} → should be allowed")
        listener_create(cli, admin_test_listener, "http", port=19098)
        admin_listener_created = True
        print("  [admin] listener create allowed ✓")

        # ── Step 9: Admin token → agent exec (not RBAC-rejected) ─────────────
        #
        # We call exec on a non-existent agent. The request may fail (agent not
        # found), but it must NOT fail with exit code 3 (RBAC rejection).
        print("  [admin] agent exec on dummy id → should not be RBAC-rejected")
        try:
            agent_exec(cli, "00000000-0000-0000-0000-000000000000", "whoami")
            # Unexpected success (e.g. a live agent happened to have that id), that's fine.
        except CliError as exc:
            assert exc.exit_code != 3, (
                f"admin was RBAC-rejected for 'agent exec' (exit 3) — RBAC broken: {exc}"
            )
            print(f"  [admin] agent exec failed as expected (non-RBAC, exit {exc.exit_code})")
        print("  [admin] agent exec not RBAC-rejected ✓")

        # ── Step 10: Admin token → operator create (allowed) ─────────────────
        print(f"  [admin] operator create {admin_test_operator!r} → should be allowed")
        result = operator_create(cli, admin_test_operator, "temp-pass-" + uid, "analyst")
        assert result.get("username") == admin_test_operator, (
            f"admin operator create returned unexpected username: {result.get('username')!r}"
        )
        admin_operator_created = True
        print("  [admin] operator create allowed ✓")

        print("  [suite] all RBAC checks passed")

    finally:
        # ── Step 11: Cleanup ───────────────────────────────────────────────────
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
