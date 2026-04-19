"""
Scenario 03_payload_build: Payload generation

Build payloads for all arch×format combos and validate.

Tests:
- Build EXE x64 → output is valid PE (MZ header check)
- Build EXE x86 → valid PE
- Build BIN (raw shellcode) x64 → non-empty bytes returned
- Build DLL x64 → valid PE (MZ header check)
- Build with no listener selected → meaningful error returned
- Build request with invalid format → error code returned
- Cache hit: build same config twice, second is faster (timestamp comparison)
"""

DESCRIPTION = "Payload generation"

import time
import uuid


# MZ magic bytes that begin every valid Windows PE file.
_PE_MAGIC = b"MZ"


def _short_id():
    """Return a short unique hex suffix to avoid name collisions across test runs."""
    return uuid.uuid4().hex[:8]


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
    from lib.cli import CliError, listener_create, listener_delete, payload_build, payload_build_and_fetch, payload_cache_flush

    cli = ctx.cli
    uid = _short_id()
    listener_name = f"test-payload-{uid}"

    # Create a temporary HTTP listener that the payloads will point back to.
    # Use a high-numbered port that doesn't require elevated privileges.
    listener_port = ctx.env.get("listeners", {}).get("payload_build_port", 19080)
    listener_create(cli, listener_name, "http", port=listener_port)

    try:
        # ── Test 1: EXE x64 → valid PE ───────────────────────────────────────
        print("  [exe-x64] building EXE x64")
        raw = payload_build_and_fetch(cli, listener=listener_name,
                                      arch="x64", fmt="exe")
        assert len(raw) > 0, "EXE x64 payload is empty"
        assert _is_valid_pe(raw), (
            f"EXE x64 payload does not start with MZ magic: "
            f"first 4 bytes = {raw[:4]!r}"
        )
        print(f"  [exe-x64] passed ({len(raw)} bytes)")

        # ── Test 2: EXE x86 → valid PE ───────────────────────────────────────
        print("  [exe-x86] building EXE x86")
        raw = payload_build_and_fetch(cli, listener=listener_name,
                                      arch="x86", fmt="exe")
        assert len(raw) > 0, "EXE x86 payload is empty"
        assert _is_valid_pe(raw), (
            f"EXE x86 payload does not start with MZ magic: "
            f"first 4 bytes = {raw[:4]!r}"
        )
        print(f"  [exe-x86] passed ({len(raw)} bytes)")

        # ── Test 3: BIN (raw shellcode) x64 → non-empty bytes ────────────────
        print("  [bin-x64] building raw shellcode (bin) x64")
        raw = payload_build_and_fetch(cli, listener=listener_name,
                                      arch="x64", fmt="bin")
        assert len(raw) > 0, "BIN x64 payload is empty"
        print(f"  [bin-x64] passed ({len(raw)} bytes)")

        # ── Test 4: DLL x64 → valid PE ───────────────────────────────────────
        print("  [dll-x64] building DLL x64")
        raw = payload_build_and_fetch(cli, listener=listener_name,
                                      arch="x64", fmt="dll")
        assert len(raw) > 0, "DLL x64 payload is empty"
        assert _is_valid_pe(raw), (
            f"DLL x64 payload does not start with MZ magic: "
            f"first 4 bytes = {raw[:4]!r}"
        )
        print(f"  [dll-x64] passed ({len(raw)} bytes)")

        # ── Test 5: No listener → meaningful error ───────────────────────────
        print("  [no-listener] testing build with no listener")
        try:
            payload_build(cli, listener="", arch="x64", fmt="exe", wait=True)
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

        # ── Test 6: Invalid format → error code ─────────────────────────────
        print("  [invalid-format] testing build with invalid format")
        try:
            payload_build(cli, listener=listener_name,
                          arch="x64", fmt="shellcode-raw", wait=True)
            raise AssertionError(
                "payload_build with invalid format succeeded — "
                "expected a CliError"
            )
        except CliError as exc:
            assert exc.exit_code != 0, (
                f"expected non-zero exit code for invalid format, "
                f"got {exc.exit_code}"
            )
        print("  [invalid-format] passed")

        # ── Test 7: Cache hit — second build is faster ───────────────────────
        #
        # Build the same config twice. The second build should use a cached
        # artifact and complete significantly faster than the first.
        # Flush before measuring so the first build is always a real compile.
        print("  [cache-hit] testing build cache")
        payload_cache_flush(cli)

        t0 = time.monotonic()
        payload_build_and_fetch(cli, listener=listener_name,
                                arch="x64", fmt="exe")
        first_elapsed = time.monotonic() - t0

        t0 = time.monotonic()
        payload_build_and_fetch(cli, listener=listener_name,
                                arch="x64", fmt="exe")
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
