"""
Shared utilities for the Red Cell C2 automated test harness.
"""


class ScenarioSkipped(Exception):
    """Raised by a scenario's run() function to signal a deliberate skip.

    Use this instead of a bare ``return`` when a precondition is not met (e.g.
    missing target, unconfigured credential, feature not yet implemented).
    The harness catches this exception, reports the scenario as **skipped**
    (not failed), and continues with the remaining scenarios.

    Usage inside a scenario::

        from lib import ScenarioSkipped

        def run(ctx):
            if ctx.windows is None:
                raise ScenarioSkipped("no Windows target configured")
            ...
    """
