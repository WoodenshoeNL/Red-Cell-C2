# Known Flaky Tests

**Purpose**: Tests that intermittently fail due to timing, port conflicts, shared resources,
or concurrency — not because of a code bug. Before spending turns diagnosing a test failure,
check here. If the test is listed, the flakiness is a known infrastructure issue, not your code.

This file covers *intermittent* failures. For *persistent* failures (always broken), see
`docs/known-failures.md`.

---

## How to check before diagnosing

```bash
# Quick check — does this test name appear here?
grep -i "<test_name_keyword>" docs/known-flaky-tests.md
```

If it does: re-run the test 2–3 times in isolation before concluding it is your fault.

```bash
cargo nextest run -p red-cell --test <test_file> <test_name> --no-capture
```

If it passes in isolation but fails in the full suite, it is a resource-conflict flake —
not a regression you introduced.

---

## Category 1 — Port-binding races

These tests bind to a real TCP/UDP port. When run in parallel with other port-binding tests
on the same machine, `EADDRINUSE` causes them to fail.

**Protected by**: nextest serial groups (see `.cargo/nextest.toml`, `[[profile.default.overrides]]`
sections with `test-threads = 1`).

**What to do if you see EADDRINUSE failures**:
1. Check that the test is in the correct nextest serial group.
2. If not, add it: edit `.cargo/nextest.toml` and add the test name to the relevant
   `[[profile.default.overrides]]` block with `test-threads = 1`.
3. File a beads issue with `zone:teamserver` if the serial group is missing.

**Known port-binding test groups**:

| nextest group | Tests covered | Reason |
|---------------|--------------|--------|
| `net_dispatch` | `teamserver/tests/net_dispatch*.rs` | Bind to listener ports |
| `output_dispatch` binary | `output_dispatch` binary tests | Bind to fixed ports |
| `http_listener_pipeline` | `teamserver/tests/http_listener_pipeline.rs` | Axum listener on a fixed port |

---

## Category 2 — Shared in-process state

These tests mutate global or static state and must not run concurrently with others in the
same process.

### `rapid_reconnect_callback_cycles`

**File**: `teamserver/tests/` (rate-limiter tests)

**Symptom**: Fails when the per-agent reconnect rate limiter from a previous test leaks into
this test's window, causing it to be rate-limited before the expected reconnect cycle completes.

**Tracking**: red-cell-c2-dy2ld (open — rate limiter state isolation not yet fixed)

**Workaround**: Run in isolation. Do not treat a failure here as a regression unless you
changed rate-limiter code.

### `repeated_wrong_passwords_trigger_rate_limiter_lockout`

**File**: `teamserver/src/auth.rs`

**Symptom**: Receives `Close(None)` instead of the expected `InitConnectionError` frame.
The close is sent by the rate limiter before the full error response is written when
another test has recently exhausted the same global limiter bucket.

**Tracking**: red-cell-c2-rlt01 (open)

**Workaround**: Run in isolation. Do not conflate with auth logic regressions.

---

## Category 3 — Timing / sleep-dependent tests

Tests that use `sleep` or `timeout` to wait for async events. They pass on fast machines
but time out on loaded VMs (e.g. during a concurrent `cargo nextest run --workspace`).

**General rule**: If a test times out but passes in isolation, it is a flake. Do not widen
the timeout in the test — file an issue to replace the `sleep` with a proper poll loop using
`tokio::time::timeout` + a channel or condition variable.

---

## Category 4 — Build lock / resource exhaustion

### lld SIGBUS during linking

**Tests**: `mock_demon_agent_checkin`, `load_and_chaos`

**Symptom**: `rust-lld` crashes with SIGBUS during the link phase after a full workspace
build has exhausted RAM. Non-deterministic — only occurs under memory pressure.

**See also**: `docs/known-failures.md` → "lld Bus error (SIGBUS) during linking"

**What to do**: Free RAM (kill unneeded processes), then re-run. Not your code.

---

## How to add a new entry

When you confirm a test is intermittently flaky (passes in isolation, fails in the full suite
or on repeated runs):

1. Add an entry to this file under the appropriate category.
2. Include: test file path, symptom, repro command, tracking issue ID (create one if needed).
3. Commit the update as part of the session that discovered the flake.

```bash
git add docs/known-flaky-tests.md
git commit -m "docs: add <test_name> to known-flaky-tests"
```

---

## Maintenance

When a flaky test is fixed (serial group added, state isolation fixed, etc.):
- Remove it from this file.
- Close or update the tracking beads issue.
- Add a one-line entry to the "Resolved" section of `docs/known-failures.md` for 7 days.
