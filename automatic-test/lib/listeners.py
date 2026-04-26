"""
lib/listeners.py — helpers for constructing HTTP listener configurations.

Centralises the ``[server].callback_host`` plumbing that scenarios deploying
agents to remote VMs require. Without ``callback_host`` the teamserver bakes
``127.0.0.1`` into the Demon/Archon CONFIG_BYTES, and the agent then calls its
own loopback on the target VM and never reaches the teamserver.
"""

from __future__ import annotations

from typing import Any


def http_listener_kwargs(
    port: int,
    env: dict,
    *,
    agent_type: str | None = None,
) -> dict[str, Any]:
    """Build kwargs for ``listener_create(cli, name, "http", **kwargs)``.

    Reads ``[server].callback_host`` from *env*. If set, adds it as ``hosts`` so
    the teamserver bakes the routable address into agent CONFIG_BYTES. If
    absent, returns just ``port`` and the teamserver falls back to its default
    bind address (``127.0.0.1``) — only suitable when the agent runs on the
    same machine as the teamserver.

    When *agent_type* is ``"demon"`` the listener is created in legacy mode
    (``--legacy-mode``) because the frozen Demon agent sends the Demon header
    format (``size | 0xDEADBEEF | agent_id``), not the Archon format.
    """
    kw: dict[str, Any] = {"port": port}
    callback_host = env.get("server", {}).get("callback_host")
    if callback_host:
        kw["hosts"] = callback_host
    if agent_type and agent_type.lower() == "demon":
        kw["legacy_mode"] = True
    return kw
