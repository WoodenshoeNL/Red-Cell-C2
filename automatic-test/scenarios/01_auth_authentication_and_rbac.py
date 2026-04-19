"""
Scenario 01: Authentication and RBAC

Verifies the five auth/RBAC properties of the teamserver REST API:

  1. Login with valid credentials   → token accepted, status succeeds
  2. Login with invalid credentials → exit code 3
  3. Token used for authenticated request → success (agent list)
  4. Viewer-role token rejected for operator-only actions → exit code 3
     (skipped when analyst_operator.api_key is absent / empty in env.toml)
  5. Expired / revoked token rejected → exit code 3

All interaction goes through red-cell-cli via lib/cli.py helpers.
"""

DESCRIPTION = "Authentication and RBAC"


def run(ctx):
    """
    ctx.cli     — CliConfig with a valid admin API key
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raises AssertionError with a descriptive message on any failure.
    """
    from lib.cli import CliConfig, CliError, login, status, agent_list

    cli = ctx.cli
    env = ctx.env

    # ── Test 1: Valid credentials → token returned ────────────────────────────
    #
    # The REST API uses static API keys (no username/password login endpoint).
    # login() validates the key via a status call and returns it unchanged.
    token = login(cli)
    assert token, "login() returned an empty token for valid credentials"
    assert token == cli.token, (
        f"login() must return the active API key: "
        f"expected {cli.token!r}, got {token!r}"
    )

    # ── Test 2: Invalid credentials → exit code 3 ─────────────────────────────
    bad_cfg = cli.with_token("invalid-bad-token-xyz123")
    try:
        login(bad_cfg)
        raise AssertionError(
            "login() with an invalid token succeeded — expected exit code 3"
        )
    except CliError as exc:
        assert exc.exit_code == 3, (
            f"expected exit code 3 for invalid credentials, got {exc.exit_code}: {exc}"
        )

    # ── Test 3: Token used for authenticated request → success ─────────────────
    agents = agent_list(cli)
    assert isinstance(agents, list), (
        f"authenticated request (agent list) did not return a list: {agents!r}"
    )

    # ── Test 4: Viewer-role token rejected for operator-only action ────────────
    #
    # operator create requires admin role — an analyst-role key must be rejected.
    # Skipped when env.toml does not have a non-empty analyst_operator.api_key.
    analyst_key = env.get("analyst_operator", {}).get("api_key", "")
    if analyst_key:
        from lib.cli import operator_create
        analyst_cfg = cli.with_token(analyst_key)
        try:
            operator_create(
                analyst_cfg,
                username="_rbac-probe-01_",
                password="probe-pass-xyz",
                role="operator",
            )
            raise AssertionError(
                "analyst-role token was not rejected for 'operator create' — RBAC broken"
            )
        except CliError as exc:
            assert exc.exit_code == 3, (
                f"expected exit code 3 for RBAC rejection (analyst cannot create operators), "
                f"got {exc.exit_code}: {exc}"
            )
    else:
        print(
            "  [SKIP] viewer-role RBAC test — "
            "set analyst_operator.api_key in config/env.toml to enable"
        )

    # ── Test 5: Expired / revoked token rejected ───────────────────────────────
    expired_cfg = cli.with_token("expired-token-00000000-0000-0000-0000-000000000000")
    try:
        status(expired_cfg)
        raise AssertionError(
            "expired/revoked token was accepted — expected exit code 3"
        )
    except CliError as exc:
        assert exc.exit_code == 3, (
            f"expected exit code 3 for expired token, got {exc.exit_code}: {exc}"
        )
