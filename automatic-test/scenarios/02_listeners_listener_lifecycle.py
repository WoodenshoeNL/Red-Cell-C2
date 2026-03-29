"""
Scenario 02_listeners: Listener lifecycle

Create, start, stop, and delete HTTP/DNS/SMB listeners
"""

DESCRIPTION = "Listener lifecycle"


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raise any exception to mark the scenario as FAILED.
    """
    raise NotImplementedError("Scenario 02_listeners not yet implemented")
