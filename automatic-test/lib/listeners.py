"""
lib/listeners.py — helpers for constructing HTTP listener configurations.

Centralises the ``[server].callback_host`` plumbing that scenarios deploying
agents to remote VMs require. Without ``callback_host`` the teamserver bakes
``127.0.0.1`` into the Demon/Archon CONFIG_BYTES, and the agent then calls its
own loopback on the target VM and never reaches the teamserver.
"""

from __future__ import annotations

from typing import Any


def normalize_callback_host_for_listener(value: str) -> str:
    """Return the routable host part of *value*; listener port is ``port_bind`` only.

    ``pack_http_listener`` (teamserver) treats ``hosts[]`` entries that contain
    ``host:port`` as authoritative for **both** host and port. If env.toml has
    ``[server].callback_host = "10.0.0.1:19081"`` but the scenario uses a
    different listener port (e.g. 19082), the baked CONFIG_BYTES would call the
    wrong port and the agent would never reach this listener. Stripping a
    trailing ``:port`` for common ``IPv4`` / ``name:port`` forms keeps
    ``port_bind`` from the listener create call as the single port source, matching
    :func:`lib.resilience.http_listener_inner_config` (``host:scenario_port`` there).

    Bracketed IPv6 (``[addr]:port``) is supported; unbracketed IPv6 is passed through.
    """
    s = str(value).strip()
    if not s:
        return s
    if s.startswith("["):
        # "[addr]:port" or "[addr]"
        p = s.find("]:")
        if p != -1:
            return s[: p + 1]
        return s
    # Single colon: IPv4 "a.b.c.d:port" or "hostname:port"
    if s.count(":") == 1:
        host, maybe_port = s.split(":", 1)
        if maybe_port.isdigit() and 0 < int(maybe_port) < 65536:
            return host
    return s


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

    The host string is normalised with :func:`normalize_callback_host_for_listener` so
    a mistaken ``:port`` suffix in env.toml does not override the *listener*'s
    ``--port`` / ``port_bind`` used for this scenario.

    When *agent_type* is ``"demon"`` the listener is created in legacy mode
    (``--legacy-mode``) because the frozen Demon agent sends the Demon header
    format (``size | 0xDEADBEEF | agent_id``), not the Archon format.
    """
    kw: dict[str, Any] = {"port": port}
    callback_host = env.get("server", {}).get("callback_host")
    if callback_host:
        kw["hosts"] = normalize_callback_host_for_listener(str(callback_host))
    if agent_type and agent_type.lower() == "demon":
        kw["legacy_mode"] = True
    return kw
