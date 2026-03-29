"""
Scenario 12_rbac: RBAC enforcement

Verify role-based access control across all endpoints
"""

DESCRIPTION = "RBAC enforcement"


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raise any exception to mark the scenario as FAILED.
    """
    raise NotImplementedError("Scenario 12_rbac not yet implemented")
