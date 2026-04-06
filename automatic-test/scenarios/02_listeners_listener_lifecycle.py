"""
Scenario 02_listeners: Listener lifecycle

Create, start, stop, and delete HTTP/DNS/SMB listeners.

Tests:
- Create HTTP listener → appears in listener list
- Start listener → status becomes 'running', TCP port is open (HTTP only)
- Stop listener → status becomes 'stopped'
- Delete listener → no longer in list
- Repeat for DNS and SMB listener types
- Duplicate name rejected with exit code 1
"""

DESCRIPTION = "Listener lifecycle"

import uuid

from lib.wait import wait_for_port


def _short_id():
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _extract_host(url):
    """Extract the bare hostname from a URL such as wss://127.0.0.1:40056."""
    if "://" in url:
        url = url.split("://", 1)[1]
    return url.split(":")[0].split("/")[0]


def _lifecycle_test(cli, host, name, listener_type, create_kwargs, check_port=None):
    """
    Run the full create → start → stop → delete lifecycle for one listener type.

    check_port: if not None, verify the TCP port is reachable after start.
    """
    from lib.cli import (
        listener_create,
        listener_delete,
        listener_list,
        listener_start,
        listener_stop,
    )

    # ── Create ───────────────────────────────────────────────────────────────
    detail = listener_create(cli, name, listener_type, **create_kwargs)
    assert detail.get("name") == name, (
        f"create returned name {detail.get('name')!r}, expected {name!r}"
    )

    # ── Appears in list ───────────────────────────────────────────────────────
    listeners = listener_list(cli)
    listed_names = [row["name"] for row in listeners]
    assert name in listed_names, (
        f"newly created listener {name!r} not in list after create: {listed_names}"
    )

    # ── Start ────────────────────────────────────────────────────────────────
    result = listener_start(cli, name)
    status = result.get("status", "")
    assert status.lower() == "running", (
        f"listener {name!r} status after start is {status!r}, expected 'running'"
    )

    # Verify via list
    row = next(
        (r for r in listener_list(cli) if r["name"] == name),
        None,
    )
    assert row is not None, f"listener {name!r} disappeared from list after start"
    assert row["status"].lower() == "running", (
        f"list shows status {row['status']!r} after start, expected 'running'"
    )

    # Optional TCP connectivity check (HTTP only; DNS is UDP, SMB uses named pipes)
    if check_port is not None:
        wait_for_port(host, check_port)

    # ── Stop ─────────────────────────────────────────────────────────────────
    result = listener_stop(cli, name)
    status = result.get("status", "")
    assert status.lower() == "stopped", (
        f"listener {name!r} status after stop is {status!r}, expected 'stopped'"
    )

    # Verify via list
    row = next(
        (r for r in listener_list(cli) if r["name"] == name),
        None,
    )
    assert row is not None, f"listener {name!r} disappeared from list after stop"
    assert row["status"].lower() == "stopped", (
        f"list shows status {row['status']!r} after stop, expected 'stopped'"
    )

    # ── Delete ───────────────────────────────────────────────────────────────
    deleted = listener_delete(cli, name)
    assert deleted.get("deleted") is True, (
        f"listener_delete did not return deleted=true: {deleted!r}"
    )

    # Verify gone from list
    listed_names = [r["name"] for r in listener_list(cli)]
    assert name not in listed_names, (
        f"deleted listener {name!r} still in listener list: {listed_names}"
    )


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raises AssertionError with a descriptive message on any failure.
    """
    from lib.cli import CliError, listener_create, listener_delete

    cli = ctx.cli
    env = ctx.env

    # Extract the teamserver host for TCP port-open checks.
    server_url = (
        env.get("server", {}).get("rest_url")
        or env.get("server", {}).get("url", "")
    )
    host = _extract_host(server_url) or "127.0.0.1"

    # Unique suffix per run to avoid collisions with existing or parallel runs.
    uid = _short_id()
    http_name = f"test-http-{uid}"
    dns_name = f"test-dns-{uid}"
    smb_name = f"test-smb-{uid}"

    # High-numbered ports that don't require elevated privileges.
    http_port = 18080
    dns_port = 15353

    # Track created-but-not-yet-deleted listeners for cleanup on failure.
    active = []

    try:
        # ── HTTP listener ─────────────────────────────────────────────────────
        print(f"  [HTTP] {http_name}")
        active.append(http_name)
        _lifecycle_test(
            cli, host, http_name, "http",
            create_kwargs={"port": http_port},
            check_port=http_port,
        )
        active.remove(http_name)
        print("  [HTTP] passed")

        # ── DNS listener ──────────────────────────────────────────────────────
        print(f"  [DNS] {dns_name}")
        active.append(dns_name)
        _lifecycle_test(
            cli, host, dns_name, "dns",
            create_kwargs={"port": dns_port, "domain": "c2.test.local"},
            check_port=None,  # DNS is UDP; TCP port check is not meaningful
        )
        active.remove(dns_name)
        print("  [DNS] passed")

        # ── SMB listener ──────────────────────────────────────────────────────
        print(f"  [SMB] {smb_name}")
        active.append(smb_name)
        _lifecycle_test(
            cli, host, smb_name, "smb",
            create_kwargs={"pipe_name": f"redcell-{uid}"},
            check_port=None,  # SMB uses named pipes, not TCP ports
        )
        active.remove(smb_name)
        print("  [SMB] passed")

    except Exception:
        # Best-effort cleanup of any listeners left in a partial state.
        for name in list(active):
            try:
                listener_delete(cli, name)
            except Exception:
                pass
        raise

    # ── Duplicate name rejection ──────────────────────────────────────────────
    #
    # The server returns HTTP 409 Conflict which maps to CliError (exit code 1).
    print("  [duplicate] testing duplicate name rejection")
    dup_name = f"test-dup-{uid}"
    listener_create(cli, dup_name, "http", port=http_port)
    try:
        try:
            listener_create(cli, dup_name, "http", port=http_port + 1)
            raise AssertionError(
                f"duplicate listener name {dup_name!r} was accepted — expected exit code 1"
            )
        except CliError as exc:
            assert exc.exit_code == 1, (
                f"expected exit code 1 for duplicate listener name, "
                f"got {exc.exit_code}: {exc}"
            )
    finally:
        try:
            listener_delete(cli, dup_name)
        except Exception:
            pass
    print("  [duplicate] passed")
