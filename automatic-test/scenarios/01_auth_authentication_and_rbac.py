"""
Scenario 01_auth: Authentication and RBAC

Test login, token validity, role enforcement
"""

DESCRIPTION = "Authentication and RBAC"


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raise any exception to mark the scenario as FAILED.
    """
    raise NotImplementedError("Scenario 01_auth not yet implemented")
