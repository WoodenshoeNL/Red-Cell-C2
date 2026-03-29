"""
Scenario 05_agent_windows: Windows agent checkin

Deploy Demon to Windows 11 via SSH, wait for checkin, run command suite
"""

DESCRIPTION = "Windows agent checkin"


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raise any exception to mark the scenario as FAILED.
    """
    raise NotImplementedError("Scenario 05_agent_windows not yet implemented")
