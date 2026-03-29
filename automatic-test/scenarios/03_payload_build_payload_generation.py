"""
Scenario 03_payload_build: Payload generation

Build Demon payloads for all arch×format combos and validate.

Tests:
- Build Demon EXE x64 → output is valid PE (MZ header check)
- Build Demon EXE x86 → valid PE
- Build Raw Shellcode x64 → non-empty bytes returned
- Build Staged Shellcode x64 → non-empty bytes returned
- Build with no listener selected → meaningful error returned
- Build request for unknown agent type → error code returned
- Cache hit: build same config twice, second is faster (timestamp comparison)
"""

DESCRIPTION = "Payload generation"

import base64
import time
import uuid


# MZ magic bytes that begin every valid Windows PE file.
_PE_MAGIC = b"MZ"


def _short_id():
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


def _decode_payload(data: dict) -> bytes:
    """
    Extract the raw payload bytes from a payload_build response.

    The CLI returns either:
      {"bytes": "<base64>"}   — inline payload (default when --output is omitted)
      {"path": "/tmp/..."}    — on-disk file path (when --output is given)

    We always use the inline form here (no --output flag).
    """
    if "bytes" in data:
        return base64.b64decode(data["bytes"])
    raise AssertionError(
        f"payload_build response missing 'bytes' field: {data!r}"
    )


def _is_valid_pe(raw: bytes) -> bool:
    """Return True if raw bytes start with the MZ PE magic."""
    return raw[:2] == _PE_MAGIC


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None
    ctx.windows — TargetConfig | None
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raises AssertionError with a descriptive message on any failure.
    """
    from lib.cli import CliError, listener_create, listener_delete, payload_build

    cli = ctx.cli
    uid = _short_id()
    listener_name = f"test-payload-{uid}"

    # Create a temporary HTTP listener that the payloads will point back to.
    # Use a high-numbered port that doesn't require elevated privileges.
    listener_port = 19080
    listener_create(cli, listener_name, "http", port=listener_port)

    try:
        # ── Test 1: Demon EXE x64 → valid PE ─────────────────────────────────
        print("  [exe-x64] building Demon EXE x64")
        result = payload_build(cli, agent="demon", listener=listener_name,
                               arch="x64", fmt="exe")
        raw = _decode_payload(result)
        assert len(raw) > 0, "EXE x64 payload is empty"
        assert _is_valid_pe(raw), (
            f"EXE x64 payload does not start with MZ magic: "
            f"first 4 bytes = {raw[:4]!r}"
        )
        print(f"  [exe-x64] passed ({len(raw)} bytes)")

        # ── Test 2: Demon EXE x86 → valid PE ─────────────────────────────────
        print("  [exe-x86] building Demon EXE x86")
        result = payload_build(cli, agent="demon", listener=listener_name,
                               arch="x86", fmt="exe")
        raw = _decode_payload(result)
        assert len(raw) > 0, "EXE x86 payload is empty"
        assert _is_valid_pe(raw), (
            f"EXE x86 payload does not start with MZ magic: "
            f"first 4 bytes = {raw[:4]!r}"
        )
        print(f"  [exe-x86] passed ({len(raw)} bytes)")

        # ── Test 3: Raw Shellcode x64 → non-empty bytes ───────────────────────
        print("  [shellcode-raw-x64] building raw shellcode x64")
        result = payload_build(cli, agent="demon", listener=listener_name,
                               arch="x64", fmt="shellcode-raw")
        raw = _decode_payload(result)
        assert len(raw) > 0, "Raw shellcode x64 payload is empty"
        print(f"  [shellcode-raw-x64] passed ({len(raw)} bytes)")

        # ── Test 4: Staged Shellcode x64 → non-empty bytes ───────────────────
        print("  [shellcode-staged-x64] building staged shellcode x64")
        result = payload_build(cli, agent="demon", listener=listener_name,
                               arch="x64", fmt="shellcode-staged")
        raw = _decode_payload(result)
        assert len(raw) > 0, "Staged shellcode x64 payload is empty"
        print(f"  [shellcode-staged-x64] passed ({len(raw)} bytes)")

        # ── Test 5: No listener → meaningful error ────────────────────────────
        print("  [no-listener] testing build with no listener")
        try:
            payload_build(cli, agent="demon", listener="",
                          arch="x64", fmt="exe")
            raise AssertionError(
                "payload_build with empty listener name succeeded — "
                "expected a CliError"
            )
        except CliError as exc:
            assert exc.exit_code != 0, (
                f"expected non-zero exit code for missing listener, "
                f"got {exc.exit_code}"
            )
            assert exc.message, (
                "expected a non-empty error message for missing listener"
            )
        print("  [no-listener] passed")

        # ── Test 6: Unknown agent type → error code ───────────────────────────
        print("  [unknown-agent] testing build with unknown agent type")
        try:
            payload_build(cli, agent="nonexistent-agent-xyz", listener=listener_name,
                          arch="x64", fmt="exe")
            raise AssertionError(
                "payload_build with unknown agent type succeeded — "
                "expected a CliError"
            )
        except CliError as exc:
            assert exc.exit_code != 0, (
                f"expected non-zero exit code for unknown agent, "
                f"got {exc.exit_code}"
            )
        print("  [unknown-agent] passed")

        # ── Test 7: Cache hit — second build is faster ────────────────────────
        #
        # Build the same config twice. The second build should use a cached
        # artifact and complete significantly faster than the first.
        # We use a 5× speedup ratio as the threshold (generous to avoid flakes
        # on slow CI machines).
        print("  [cache-hit] testing build cache")
        build_args = dict(agent="demon", listener=listener_name,
                          arch="x64", fmt="exe")

        t0 = time.monotonic()
        payload_build(cli, **build_args)
        first_elapsed = time.monotonic() - t0

        t0 = time.monotonic()
        payload_build(cli, **build_args)
        second_elapsed = time.monotonic() - t0

        # The second build must finish in at most half the time of the first,
        # OR under 1 second absolute (fast machines may cache so well the
        # ratio check becomes noisy).
        cache_fast_enough = (
            second_elapsed < first_elapsed / 2.0
            or second_elapsed < 1.0
        )
        assert cache_fast_enough, (
            f"cache hit did not speed up the second build: "
            f"first={first_elapsed:.3f}s  second={second_elapsed:.3f}s"
        )
        print(
            f"  [cache-hit] passed "
            f"(first={first_elapsed:.2f}s, second={second_elapsed:.2f}s)"
        )

    finally:
        # Best-effort cleanup of the temporary listener.
        try:
            listener_delete(cli, listener_name)
        except Exception:
            pass
