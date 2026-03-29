"""
Scenario 11_loot_audit: Loot and audit log

Verify loot entries and audit log completeness
"""

DESCRIPTION = "Loot and audit log"


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raise any exception to mark the scenario as FAILED.
    """
    raise NotImplementedError("Scenario 11_loot_audit not yet implemented")
