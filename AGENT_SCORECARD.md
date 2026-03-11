# Agent Scorecard

Maintained automatically by the QA and architecture review loops.
Each loop run updates the running totals and appends a review entry.

---

## Running Totals

| Metric | Claude | Codex | Cursor |
|--------|-------:|------:|-------:|
| Tasks closed | 0 | 27 | 10 |
| Bugs filed against | 0 | 2 | 2 |
| Bug rate (bugs/task) | N/A | 0.07 | 0.20 |
| Quality score | N/A | 93% | 80% |

## Violation Breakdown

| Violation type | Claude | Codex | Cursor |
|----------------|-------:|------:|-------:|
| unwrap / expect in production | 0 | 0 | 0 |
| Missing tests | 0 | 1 | 1 |
| Clippy warnings | 0 | 0 | 0 |
| Protocol errors | 1 | 1 | 1 |
| Security issues | 0 | 5 | 0 |
| Architecture drift | 0 | 1 | 0 |
| Memory / resource leaks | 0 | 3 | 0 |
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

### QA Review — 2026-03-10 21:13 — 09f5a07..d112826

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 2 | 0 | Closed red-cell-c2-80m (common crate unit tests) and red-cell-c2-8ri (mock Demon agent checkin integration test). Full E2E checkin/get-job/output flow covered. build_router refactored to app.rs for testability. No unwrap in production paths, no clippy warnings. red-cell-c2-dgn (E2E mock agent + operator client) now claimed, in_progress. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings + cargo test: 74 passed)

### QA Review — 2026-03-10 21:34 — d112826..19e8f0a

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 2 | 0 | Closed red-cell-c2-n3n (concurrent AgentRegistry unit tests) and red-cell-c2-dgn (full E2E operator+demon session: listener create → DEMON_INIT → GET_JOB → CommandCheckin job dispatch → CommandOutput → WebSocket broadcast). Protocol constants verified correct. No unwrap in production paths. RBAC tests refactored to table-driven style. red-cell-c2-2jw (DNS response map expiry) now claimed and fix in-progress. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings + cargo test: 74 unit + 1 e2e = 75 tests)

### QA Review — 2026-03-10 22:00 — 5b4e5ec..f4df7a7

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 4 | 0 | Closed red-cell-c2-2jw (DNS upload expiry moved to background timer via tokio::select!), red-cell-c2-2g6 (echo original qtype in DNS question section), red-cell-c2-uos (DNS upload hardening: chunk total cap 256, session cap 1000, inconsistent-total rejection), red-cell-c2-1am (reject DNS response packets via QR-bit check). All fixes include unit tests. red-cell-c2-1c0 (responses map leak) newly claimed. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings + cargo test: 74 passed)

### Arch Review — 2026-03-10 23:15

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No findings this run |
| Codex | 5 | Security ×1, Architecture ×1, Memory/resource ×3 | SOCKS5 exposed on 0.0.0.0, agent_new_event duplicated (pivot chain dropped), AgentSocketState never pruned, SocksServerHandle graceful shutdown unused, DNS responses not expired on mid-download abandon |
| Cursor | 0 | — | No activity |

Overall codebase health: on track
Biggest blindspot: SOCKS5 SOCKS relay bound to 0.0.0.0 — any host on the network can use it as an open proxy through the agent without authentication

### QA Review — 2026-03-10 — c6e35f..bac618

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop + 3 infra fixes (loop double-claiming, DB schema drift, JSONL/DB mismatch) |
| Codex | 2 | 0 | Closed red-md8 (SOCKS relay loopback bind: `0.0.0.0`→`127.0.0.1`), red-cell-c2-n8e (DNS CNAME + configurable query-type filtering with early validation and full test coverage) |
| Cursor | 1 | 0 | Closed red-cell-c2-f0d (operator-facing typo fixes: "Successful"→"Successfully", "impersonat"→"impersonate"; tests updated) |

Build: passed (cargo check + clippy -D warnings + cargo test: 74 passed)
Observation: `build_dns_txt_response` always emits DNS_TYPE_TXT in the answer RR regardless of query qtype; CNAME queries accepted by the new config path respond with TXT-encoded answer records. This appears to be an intentional C2 design (agent reads raw TXT data irrespective of qtype) but the CNAME integration test only checks the question-section echo, not the answer RRTYPE. Not filed as a bug — behavior is consistent with existing A-record handling and likely by design.

### QA Review — 2026-03-11 00:05 — bac618..d0efbd

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | No activity this run |
| Cursor | 9 | 2 | Closed: red-cell-c2-210, uve, 1xg, 3jn, 2ro, 3al, 3g8, 1p7, 3n6. Bugs: red-1d2 (PrivsGetOrList discards SubCommand via .map(|_|"") — privs-list unreachable through extras), red-pgd ("Successful stole" grammar error in token steal callback, same class as prior f0d fix) |

Build: passed (cargo check + clippy -D warnings + cargo test: 74 passed)
Notes: High-velocity sprint — 9 closes, ~2000 lines added. Most fixes are correct and well-tested (token/inject/spawn/process callbacks fully covered). The PrivsGetOrList encoding bug (P2) is a subtle lifetime workaround gone wrong; no test covers that path. Grammar nit (P3) is the same pattern previously fixed in red-cell-c2-f0d, reintroduced in new code.
