"""
Helpers for loading harness config into `red-cell-cli` wrapper objects.
"""

from __future__ import annotations

from .cli import CliConfig


def _resolve_cli_server(env: dict) -> str:
    server = env.get("server", {})
    if server.get("rest_url"):
        return server["rest_url"]

    raw = server.get("url", "")
    if raw.startswith("wss://"):
        return "https://" + raw[len("wss://"):]
    if raw.startswith("ws://"):
        return "http://" + raw[len("ws://"):]
    return raw


def _resolve_api_key(env: dict) -> str:
    operator = env.get("operator", {})
    api_key = operator.get("api_key", "")
    if api_key:
        return api_key
    raise KeyError(
        "config/env.toml is missing operator.api_key; "
        "the autotest harness uses static REST API keys, not operator passwords"
    )


def make_cli_config(env: dict) -> CliConfig:
    """Build the CLI wrapper config from env.toml."""
    timeouts = env.get("timeouts", {})
    return CliConfig(
        server=_resolve_cli_server(env),
        token=_resolve_api_key(env),
        timeout=timeouts.get("command_output", 30),
        max_subprocess_secs=timeouts.get("max_cli_subprocess_secs", 120),
    )
