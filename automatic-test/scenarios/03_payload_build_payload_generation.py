"""
Scenario 03_payload_build: Payload generation

Build Demon payloads for all arch×format combos and validate
"""

DESCRIPTION = "Payload generation"


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raise any exception to mark the scenario as FAILED.
    """
    raise NotImplementedError("Scenario 03_payload_build not yet implemented")
