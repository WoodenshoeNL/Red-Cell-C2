# Agent Scorecard

Maintained automatically by the QA and architecture review loops.
Each loop run updates the running totals and appends a review entry.

---

## Running Totals

| Metric | Claude | Codex | Cursor |
|--------|-------:|------:|-------:|
| Tasks closed | 0 | 6 | 0 |
| Bugs filed against | 0 | 1 | 0 |
| Bug rate (bugs/task) | N/A | 0.17 | N/A |
| Quality score | N/A | 83% | N/A |

## Violation Breakdown

| Violation type | Claude | Codex | Cursor |
|----------------|-------:|------:|-------:|
| unwrap / expect in production | 0 | 0 | 0 |
| Missing tests | 0 | 0 | 0 |
| Clippy warnings | 0 | 0 | 0 |
| Protocol errors | 0 | 0 | 0 |
| Security issues | 0 | 1 | 0 |
| Architecture drift | 0 | 0 | 0 |
| Memory / resource leaks | 0 | 0 | 0 |

---

## Review Log

<!-- QA and arch loops append entries below this line -->

### QA Review — 2026-03-10 15:49 — cfe631..0f7d29

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA/infra loop maintenance only |
| Codex | 6 | 1 | Closed: red-cell-c2-mpd, yu2, ga5, 4df, 9k8, a5n. Bug: red-cell-c2-irr (TLS cert bypass in client transport) |
| Cursor | 0 | 0 | Claimed red-cell-c2-mls and red-cell-c2-9k8, no closes yet |

Build: passed (cargo check + clippy -D warnings + cargo test: 54/54 passed)
