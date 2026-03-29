"""
Scenario 04_agent_linux: Linux agent checkin

Deploy Demon to Ubuntu, wait for checkin, run command suite
"""

DESCRIPTION = "Linux agent checkin"


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raise any exception to mark the scenario as FAILED.
    """
    raise NotImplementedError("Scenario 04_agent_linux not yet implemented")
