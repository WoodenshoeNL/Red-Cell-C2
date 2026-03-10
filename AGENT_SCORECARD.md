# Agent Scorecard

Maintained automatically by the QA and architecture review loops.
Each loop run updates the running totals and appends a review entry.

---

## Running Totals

| Metric | Claude | Codex | Cursor |
|--------|-------:|------:|-------:|
| Tasks closed | 0 | 17 | 0 |
| Bugs filed against | 0 | 2 | 0 |
| Bug rate (bugs/task) | N/A | 0.12 | N/A |
| Quality score | N/A | 88% | N/A |

## Violation Breakdown

| Violation type | Claude | Codex | Cursor |
|----------------|-------:|------:|-------:|
| unwrap / expect in production | 0 | 0 | 0 |
| Missing tests | 0 | 1 | 0 |
| Clippy warnings | 0 | 0 | 0 |
| Protocol errors | 1 | 1 | 0 |
| Security issues | 0 | 4 | 0 |
| Architecture drift | 0 | 0 | 0 |
| Memory / resource leaks | 0 | 1 | 0 |
| Audit attribution errors | 0 | 1 | 0 |

---

## Review Log

<!-- QA and arch loops append entries below this line -->

### Arch Review — 2026-03-10 16:00

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 1 | Protocol errors | DNS listeners omitted from profile startup (red-cell-c2-srf) |
| Codex | 6 | Security ×4, Memory/resource ×1, Missing tests ×1 | Timing attack on auth, unbounded HTTP body, no WS brute-force protection, agent_id=0 bypass, request_contexts leak, no E2E integration test |
| Cursor | 0 | — | No findings this run |

Overall codebase health: on track
Biggest blindspot: HTTP listener accepts arbitrarily large unauthenticated bodies — unauthenticated OOM DoS via agent-facing port

### QA Review — 2026-03-10 15:49 — cfe631..0f7d29

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA/infra loop maintenance only |
| Codex | 6 | 1 | Closed: red-cell-c2-mpd, yu2, ga5, 4df, 9k8, a5n. Bug: red-cell-c2-irr (TLS cert bypass in client transport) |
| Cursor | 0 | 0 | Claimed red-cell-c2-mls and red-cell-c2-9k8, no closes yet |

Build: passed (cargo check + clippy -D warnings + cargo test: 54/54 passed)

### QA Review — 2026-03-10 16:33 — b7c418..34d6bd

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA/arch loop maintenance only (scorecard + checkpoint commits) |
| Codex | 0 | 0 | Infra fix: hardened multi-agent loop task claiming (no task close) |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings + cargo test: 57/57 passed)

### QA Review — 2026-03-10 — 34d6bd..d19780

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop maintenance only |
| Codex | 3 | 0 | Closed red-cell-c2-8w5 (constant-time auth), red-cell-c2-1n4 (HTTP body size cap), red-cell-c2-srf (DNS listeners from profile). All fixes include tests. |
| Cursor | 0 | 0 | No activity this run (claimed red-cell-c2-1n4 but Codex landed the fix) |

Build: passed (cargo check + clippy -D warnings + cargo test: 57/57 passed)
Minor observation: `password_hashes_match` calls `to_ascii_lowercase()` before `ct_eq`; subtle's `ct_eq` short-circuits on length mismatch. Not exploitable in practice for SHA3-256 hex hashes (always 64 chars), but worth noting.

### QA Review — 2026-03-10 19:42 — 105138b..73fae9e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 2 | 1 | Closed red-cell-c2-7td (session table), red-cell-c2-7yl (loot/chat panels). Bug: red-3c6 (note task sent with empty operator username — audit attribution broken in render_note_editor). |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings + cargo test: 257 passed)

### QA Review — 2026-03-10 20:05 — 73fae9e..1e17ffc

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 2 | 0 | Closed red-cell-c2-stk (command console), red-cell-c2-8r7 (file browser panel). Clean implementation, full test coverage. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings + cargo test: 270 passed)
Note: red-cell-c2-pmq (process list panel) still in_progress — dependency on stk now resolved, should proceed.

### QA Review — 2026-03-10 20:30 — b059817..d61818c

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 2 | 0 | Closed red-cell-c2-pmq (process list panel) and red-cell-c2-wnq (session graph). Both features well-implemented with full test coverage. red-cell-c2-t9k (PyO3 client embed) just claimed, in_progress. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings + cargo test: 279 passed)

### QA Review — 2026-03-10 20:42 — d61818c..4c15400

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 2 | 0 | Closed red-cell-c2-t9k (PyO3 client embed) and red-cell-c2-vm2 (Python script manager UI). Both features well-implemented: thiserror errors, no unwrap in production paths, 6 unit tests in python.rs, test coverage for local_config changes. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings + cargo test: all passed)
