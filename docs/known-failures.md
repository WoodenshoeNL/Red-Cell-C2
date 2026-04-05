# Known Test Failures

**Purpose**: Before filing any bug about a failing test, check this file. If the test is
listed here, the bug is already tracked — do not create a duplicate issue.

This file is maintained by the QA loop and human operators. When a known failure is fixed,
remove it. When a new persistent failure is confirmed, add it.

---

## How to check before filing

```bash
grep -i "<test_name_or_keyword>" docs/known-failures.md
```

If you get a match, link your work to the existing issue instead of creating a new one:

```bash
br dep add <existing-issue-id> <your-current-issue-id>
```

---

## Active Known Failures

### http_listener_pipeline — rejects_duplicate_init_preserves_original_key

**Test**: `teamserver/tests/http_listener_pipeline.rs::http_listener_pipeline_rejects_duplicate_init_preserves_original_key`

**Symptom**: HTTP 404 when the test sends a POST to the listener's bound port — the listener
route is not mounted at `/` in the duplicate-init test path.

**Repro**:
```bash
cargo test -p red-cell --test http_listener_pipeline rejects_duplicate_init_preserves_original_key -- --exact --nocapture
```

**Tracking**: red-cell-c2-uru8k

**Zone**: teamserver

---

### payload_builder — concurrent_put_and_get_does_not_panic (flaky)

**Test**: `teamserver` — `payload_builder::tests::concurrent_put_and_get_does_not_panic`

**Symptom**: Intermittent assertion failure — `read bytes must be complete, not partially written` (left: 0, right: 2048). Race condition between truncation and write in PayloadCache under concurrent access.

**Repro**: Run repeatedly; fails non-deterministically:
```bash
cargo test -p red-cell concurrent_put_and_get_does_not_panic -- --nocapture
```

**Tracking**: red-cell-c2-ef4gw

**Zone**: teamserver

---

### auth — authenticate_login_rejects_when_global_cap_reached (slow/hanging)

**Test**: `teamserver/src/auth.rs::authenticate_login_rejects_when_global_cap_reached`

**Symptom**: Test stalls for several minutes under `cargo test --workspace` load. May
eventually pass or hang indefinitely. Not confirmed to be a deadlock vs extreme slowness.

**Repro**:
```bash
cargo test --workspace  # stalls at auth test after Specter tests complete
```

**Tracking**: red-cell-c2-swpxr

**Zone**: teamserver

---

### red-cell (test "mock_demon_agent_checkin") and (test "load_and_chaos") — lld Bus error (SIGBUS) during linking

**Tests**: `teamserver/tests/mock_demon_agent_checkin.rs`, `teamserver/tests/load_and_chaos.rs`

**Symptom**: `rust-lld` crashes with SIGBUS (signal 7 / Bus error) when linking these large
test binaries.  The crash occurs inside `llvm::parallelFor` during the link phase.  Root
cause is OOM: the machine has ~3.8 GB RAM + 3.8 GB swap and the linker exhausts memory
mapping the combined `.rlib` set (247 object files for the teamserver integration tests).

The failure is **non-deterministic** — it occurs only when available RAM is low (e.g. after
a full `cargo nextest run --workspace` run that has already exhausted the incremental cache
budget).  When RAM is plentiful the tests link and run successfully.

**Repro**:
```bash
cargo nextest run --workspace   # fails after disk/RAM is ~full from earlier compilation
```

**Tracking**: needs a beads issue (shell unavailable when first observed 2026-04-05)

**Zone**: teamserver

---

## Resolved (keep for 7 days, then remove)

### listener_lifecycle — agent_reconnects_after_listener_restart

**Fixed**: 2026-03-25 — root cause was degenerate key/IV rejection (fixed in e22fa417).
Test now passes consistently (41/41 passes across 10 full-suite runs with 8 threads).

**Was tracked as**: red-cell-c2-4wg1w (canonical), duplicates: red-cell-c2-rc51m, red-cell-c2-loti5, red-cell-c2-9ncol, red-cell-c2-rtk8g, red-cell-c2-1djk4, red-cell-c2-17v44

---

### smb_listener — 6 of 9 tests timing out

**Fixed**: 2026-03-23 — tests used degenerate AES keys rejected by server validation and
incorrect non-zero CTR offsets incompatible with legacy Demon CTR mode.

**Was tracked as**: red-cell-c2-3d6s5
