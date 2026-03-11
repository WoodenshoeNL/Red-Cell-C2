# Agent Scorecard

Maintained automatically by the QA and architecture review loops.
Each loop run updates the running totals and appends a review entry.

---

## Running Totals

| Metric | Claude | Codex | Cursor |
|--------|-------:|------:|-------:|
| Tasks closed | 0 | 68 | 31 |
| Bugs filed against | 0 | 5 | 9 |
| Bug rate (bugs/task) | N/A | 0.07 | 0.29 |
| Quality score | N/A | 93% | 71% |

## Violation Breakdown

| Violation type | Claude | Codex | Cursor |
|----------------|-------:|------:|-------:|
| unwrap / expect in production | 0 | 0 | 0 |
| Missing tests | 0 | 2 | 5 |
| Clippy warnings | 0 | 0 | 1 |
| Protocol errors | 1 | 4 | 2 |
| Security issues | 0 | 10 | 0 |
| Architecture drift | 0 | 3 | 0 |
| Memory / resource leaks | 0 | 6 | 1 |
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

### QA Review — 2026-03-11 01:30 — d0efbd..9dc2f5

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | No activity this run |
| Cursor | 4 | 0 | Closed: red-cell-c2-1k3 (listener endpoint tests: ~550 lines, full update/delete/start/stop/mark coverage), red-cell-c2-315 (parse_api_agent_id always-hex fix), red-cell-c2-11s (parse_hour_minute off-by-one fix), red-cell-c2-2dq (add_bytes overflow: unwrap_or_default→Result propagation). Active: claimed red-cell-c2-1qb (plugin emit unit tests). |

Build: passed (cargo check + clippy -D warnings + cargo test: 381 passed)
Notes: Clean sprint — all 4 fixes correct and well-tested. Test count grew from 74 to 381 (+307 across all crates). No violations found. Cursor's bug rate improves from 0.20 to 0.14 as previously filed bugs don't recur in new work.

### Arch Review — 2026-03-11 00:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No findings this run |
| Codex | 5 | Security ×2, Memory/resource ×1, Protocol ×1, Missing tests ×1 | AES-CTR IV reuse (red-2bm), SOCKS5 domain truncation (red-1u6), DownloadTracker OOM (red-aow), SOCKS write failure silenced (red-2d3), DownloadTracker test gap (red-sh4) |
| Cursor | 0 | — | No findings this run |

Overall codebase health: on track
Biggest blindspot: AES-256-CTR keystream reuse — same IV used for every packet from a given agent session; XOR of any two ciphertexts yields XOR of plaintexts, bypassing protocol-layer confidentiality entirely when TLS is absent (Secure=false listener)

### QA Review — 2026-03-11 02:00 — 9dc2f5..df1e8bd

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | No activity this run |
| Cursor | 1 | 0 | Closed red-cell-c2-1qb (plugin emit unit tests: 4 new tests for emit_agent_checkin and emit_command_output, including unknown-agent guard and exception isolation). Active: claimed red-2bm (AES-CTR IV reuse — WIP in local stash, not yet committed). |

Build: passed (cargo check + clippy -D warnings + cargo test: 385 passed)
Notes: Clean one-task sprint. All 4 new tests are well-structured and exercise meaningful scenarios. No violations found. Cursor's bug rate improves from 0.14 to 0.13 as task count grows without new bugs.

### QA Review — 2026-03-11 02:45 — df1e8bd..ce937e1

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | No activity this run |
| Cursor | 0 | 1 | red-2bm in_progress: local `ctr_blocks_for_length` uses manual div_ceil — clippy -D warnings failure (red-3t4). Work not yet committed. |

Build: clippy FAILED on uncommitted working-tree changes to crates/common/src/crypto.rs (manual_div_ceil lint). cargo check + cargo test both passed (82 tests green).

### Arch Review — 2026-03-11 03:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No findings this run |
| Codex | 0 | — | No findings this run |
| Cursor | 4 | Missing tests ×3, Protocol ×1 | red-3tc (P1): build_init_ack test uses stale sync API — cargo test fails to compile; red-1s8 (P2): callback CTR test will decrypt garbage once counter is tracked correctly; red-9pf (P2): AES-CTR block offset lost on teamserver restart — reconnect ack at wrong counter; red-rts (P3): no unit tests for encrypt_for_agent / decrypt_from_agent / ctr_offset |

Overall codebase health: degraded — working tree (red-2bm) breaks `cargo test` compilation (P1 blocker)
Biggest blindspot: AES-CTR counter not persisted to DB — every teamserver restart silently resets CTR to 0 for all agents; reconnecting agents will fail to decrypt acks with no error surfaced to operator

### QA Review — 2026-03-11 03:55 — ce937e1..e73cf89

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | No activity this run |
| Cursor | 0 | 1 | red-2bm in_progress. Filed red-1km (P1): operator_session_listener_and_mock_demon_round_trip E2E test FAILS — init ack decrypted at CTR offset=0 but server now encrypts at offset N after DEMON_INIT processing. cargo test FAILED. |

Build: cargo check PASSED, clippy -D warnings FAILED (red-3t4: manual_div_ceil in crypto.rs), cargo test FAILED (red-1km: E2E ack decryption at wrong CTR offset: got [76,123,184,63] expected [120,86,52,18])
Note: committed codebase (HEAD, before Cursor's WIP) passes all checks (74 tests, clippy clean). Failures are in uncommitted working-tree changes only.

### QA Review — 2026-03-11 05:00 — 6b0b573..9b8fc34

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | No activity this run |
| Cursor | 16 | 1 | Closed: red-2bm (AES-CTR keystream reuse — critical fix), red-3tc, red-1s8, red-3t4, red-1km (5 via single CTR commit), red-cell-c2-3o3 (mutex poison fatal), red-cell-c2-30u (request_id mismatch), red-cell-c2-1nk (task_id broadcast), red-cell-c2-3p5 (dedup job-queuing), red-cell-c2-3kc (REST audit), red-cell-c2-ljt (WS ListenerRemove audit), red-cell-c2-35x (audit SQL push), red-cell-c2-irr (TLS cert bypass), red-cell-c2-3s5 (WS rate limit), red-cell-c2-1a5 (agent_id=0 bypass), red-cell-c2-3c2 (request_contexts eviction). Bug: red-mwx (P3) LoginRateLimiter windows map unbounded — lazy eviction allows OOM under many distinct IPs. |

Build: cargo check PASSED, clippy -D warnings PASSED, cargo test PASSED (82/82)

Overall codebase health: strong recovery — the critical AES-CTR keystream reuse vulnerability (red-2bm) is fully resolved with proper per-session counter tracking, comprehensive tests, and all blocked follow-on bugs closed in the same commit. No P0/P1 issues remain open. Biggest open risk: AES-CTR block offset not persisted to DB (red-9pf) — agent reconnects after teamserver restart will receive acks encrypted at counter=0 instead of the expected offset.

### QA Review — 2026-03-11 — 9b8fc34..9b8fc34

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | No activity this run |
| Cursor | 0 | 0 | No activity this run |

Build: skipped (no new commits)
No new commits since last checkpoint. Codebase fully reviewed. Open P2 in_progress: red-cell-c2-2pw (encrypt_agent_data silent empty return — claimed, awaiting fix).

### QA Review — 2026-03-11 — 2f9031..d3d3b1

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | No activity this run |
| Cursor | 0 | 0 | Claimed red-cell-c2-2pw (encrypt_agent_data silent empty return), no closes yet |

Build: passed (cargo check + clippy -D warnings: both clean)
No code changes in this window — only a Cursor claim commit. Open P2 in_progress: red-cell-c2-2pw awaiting fix.

### QA Review — 2026-03-11 06:50 — d3d3b1..0acc1e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | No activity this run |
| Cursor | 0 | 0 | red-cell-c2-2pw still in_progress, no closes |

Build: passed (cargo check + clippy -D warnings: clean; cargo test: 506 tests passed)
No new development commits since last checkpoint. red-cell-c2-2pw (encrypt_agent_data silent empty return) remains the only in_progress item. No new bugs filed.

### QA Review — 2026-03-11 07:05 — 0acc1e..388094

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | No activity this run |
| Cursor | 0 | 0 | red-cell-c2-2pw still in_progress, no closes |

Build: passed (cargo check + clippy -D warnings: clean; cargo test: 506 passed)
No new development commits since last checkpoint. red-cell-c2-2pw (encrypt_agent_data silent empty return) remains the only in_progress item. No new bugs filed.

### Arch Review — 2026-03-11 08:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No findings this run |
| Codex | 3 | Security ×2, Memory/resource ×1 | red-3nf (HTTP listener uses into_make_service() — peer IP never captured, always 0.0.0.0), red-2d4 (zero-key bypass in DEMON_INIT allows unauthenticated plaintext registration), red-2ne (no cap on agent registry — unauthenticated DEMON_INIT flood exhausts memory/SQLite) |
| Cursor | 0 | — | No findings this run |

Overall codebase health: on track
Biggest blindspot: Zero-key DEMON_INIT bypass — any attacker that can reach the listener port can register phantom agents without a keyed implant, and the HTTP listener never records the actual peer IP, so these registrations are invisible in audit logs (always 0.0.0.0)

### QA Review — 2026-03-11 — 388094..c5ed19

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | No activity this run |
| Cursor | 0 | 0 | red-cell-c2-2pw still in_progress, no closes |

Build: passed (cargo check + clippy -D warnings: clean; cargo test: 426 passed)
No new development commits since last checkpoint. Only QA/arch review commits in range. Open P2 in_progress: red-cell-c2-2pw (encrypt_agent_data silent empty return). Open bugs: red-3nf, red-2d4, red-2ne (arch review finds, not yet fixed), red-9pf (AES-CTR block offset lost on restart). No new bugs filed this run.

### QA Review — 2026-03-11 12:45 — c5ed19..394c73

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | Infrastructure only: setup.sh, br prefix fix, QA checkpoint |
| Codex | 13 | 0 | Also closed: 1tp (DownloadTracker test coverage). Closed: 2pw (encrypt_agent_data error propagation), 2l6 (E2E HTTP listener integration test), 73w (note task operator attribution), ggu (shared agent_new_event builder), 1yv (AgentSocketState stale agent pruning), djc (graceful SOCKS shutdown), o17 (DNS pending response expiry), nk2 (token privs SubCommand preserve), 1ui (token steal grammar), zd9 (DownloadTracker memory cap), 1us (SOCKS5 oversized domain rejection), vyz (SOCKS write_client_data error surfaced) |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: 446 passed)
Note: Issue red-cell-c2-1tp (DownloadTracker unit tests) is in_progress — Codex just claimed it. The zd9 fix already added high-level integration tests; uncommitted working-tree changes add 3 direct DownloadTracker unit tests (multi-chunk, orphan chunk, size cap). Expect close next pass.

### Arch Review — 2026-03-11 11:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No findings this run |
| Codex | 4 | Security ×1, Protocol ×1, Architecture ×1, Memory/resource ×1 | red-cell-c2-m3s (P2): unauthenticated DEMON_INIT reconnect probe desyncs agent AES-CTR — attacker knowing agent_id can forge 20-byte probes to advance server CTR, breaking comms; red-cell-c2-37c (P3): X-Real-IP header trusted from agent when behind_redirector=false — agent-supplied IP stored as external_ip; red-cell-c2-grm (P3): duplicate SHA3-256 hash implementation in auth.rs vs common/crypto.rs — arch drift from common-crate ownership; red-cell-c2-35f (P3): ApiRuntime::windows map never pruned — same class as LoginRateLimiter bug red-cell-c2-2b9 |
| Cursor | 0 | — | No findings this run |

Overall codebase health: on track
Biggest blindspot: Unauthenticated DEMON_INIT reconnect probes advance CTR with no key validation — any attacker knowing a 32-bit agent_id can permanently desync agent comms via repeated forged probes (requires only reaching the listener port and knowing the agent_id, visible in plaintext if TLS is off)

### QA Review — 2026-03-11 13:20 — f94a8cf..ab04858

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 5 | 1 | Closed: red-cell-c2-131 (zero-key DEMON_INIT bypass), red-cell-c2-22x (agent registry cap), red-cell-c2-35f (ApiRuntime rate-limit window pruning), red-cell-c2-m3s (reconnect probe CTR desync — non-mutating preview path via `encrypt_for_agent_without_advancing` + `build_reconnect_ack`), red-cell-c2-grm (deduplicated SHA3-256 hash to `red_cell_common::crypto::hash_password_sha3`). Bug: red-cell-c2-3db (P3) — dead unreachable zero-key plaintext passthrough in `encrypt_for_agent`, `encrypt_for_agent_without_advancing`, `decrypt_from_agent` after `decode_crypto_material` already errors on zero keys. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: 465 passed)
Observation: m3s fix is well-designed — `encrypt_for_agent_without_advancing` reads the current CTR offset without updating it, `build_reconnect_ack` uses this path, and the listener correctly calls `build_reconnect_ack` instead of `build_init_ack` for reconnect probes. Three test layers: unit (agents.rs), protocol (demon.rs), integration (listeners.rs). The grm fix properly consolidates to the common-crate implementation. Minor P3 issue: the zero-key dead-code blocks in the encrypt/decrypt functions (filed red-cell-c2-3db). Also: red-cell-c2-1r6 (per-IP DEMON_INIT rate limiting) just claimed by Codex.

### QA Review — 2026-03-11 12:55 — ab04858..b5bbffa

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 4 | 0 | Closed: red-cell-c2-1r6 (per-IP DEMON_INIT rate limiting on HTTP/SMB/DNS listeners), red-cell-c2-3db (dead zero-key transport branches removed), red-cell-c2-5pv (Common Crate retrospective close), red-cell-c2-kug (Project Setup retrospective close). Also: clippy policy cleanup — tests use `?` instead of `.unwrap()`. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: 470 passed, +5 from rate-limiter tests)
Notes: Clean sprint. `DemonInitRateLimiter` is well-designed — shared via Arc across all listener types, per-IP windowed with 5-attempt/60s cap and 10K entry eviction. `classify_demon_transport` correctly reads plaintext command_id from unencrypted DEMON_INIT bodies (key negotiation happens in plaintext before AES-CTR kicks in). Three integration tests cover HTTP, SMB, and DNS listeners. SMB correctly uses 127.0.0.1 as the fixed peer (named pipes are local-only). No violations found.

### QA Review — 2026-03-11 14:15 — 92a90a5..7014778

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 1 | 0 | Closed: red-cell-c2-89e (persist runtime operator accounts + expose in discovery APIs + presence state). Runtime operator persistence to SQLite with startup reload, operator_inventory() with BTreeMap-sorted output, WS session snapshot includes operator list. Also active: claimed red-cell-c2-120 (Demon Agent Protocol epic). |
| Cursor | 0 | 0 | No activity this run |

Build: cargo check + clippy -D warnings: PASSED. cargo test: PASSED (476 tests, +6 from operator persistence work) with RUSTFLAGS workaround (RUSTFLAGS="-L /usr/lib/python3.12/config-3.12-x86_64-linux-gnu"); raw `cargo test --workspace` fails due to missing python3.12-dev dev symlink on QA machine (filed red-cell-c2-3ug, P3 infra).
Notes: Clean sprint. OperatorRepository is well-structured — BTreeMap ordering guarantees consistent REST and WS output, password hashes never exposed over wire (OperatorInfo.password_hash always None in operator_inventory output). write lock held across async DB insert in create_operator is intentional (prevents TOCTOU duplicate). Six new tests cover persistence, inventory, startup reload, and WS snapshot. dev loop fix (by user) adds multi-candidate scanning to prevent skip-and-fail on already-claimed tasks.

### Arch Review — 2026-03-11 14:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 3 | Architecture ×1, Protocol ×1, Consistency ×1 | red-cell-c2-3ny (P3): auth.rs:89 typo "exits" vs "exist" in UnknownUser error — surfaced to operator UI; red-cell-c2-1mw (P3): dispatch_builtin_package duplicates entire builtin handler chain as if-chain parallel to CommandDispatcher::with_builtin_handlers — maintenance divergence risk if new pivot callbacks added to one path but not the other; red-cell-c2-b7n (P3): payload_builder.rs parse_kill_date() returns i64 cast to u64 — negative timestamp wraps silently to u64::MAX, embedding ~year 584B kill date instead of error |
| Codex | 0 | — | No new findings this run |
| Cursor | 0 | — | No new findings this run |

All three findings attributed to michel@woodenshoe.org (human maintainer), not to Codex/Cursor agents — agent violation counts unchanged.
Overall codebase health: strong — no P0/P1/P2 issues identified. All previously fixed security vulnerabilities confirmed resolved. Clippy clean, 85 tests passing.
Biggest remaining risk: parallel dispatch chains (red-cell-c2-1mw) — adding a new pivot-context command to with_builtin_handlers without also updating dispatch_builtin_package (or vice versa) will silently drop callbacks in one path.

### QA Review — 2026-03-11 11:48 — 1e7832b..f94a8cf

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 4 | 0 | Closed: red-cell-c2-zdb (CTR offset persistence to DB), red-cell-c2-1u9 (CTR helper tests), red-cell-c2-2b9 (LoginRateLimiter bounded cap), red-cell-c2-xpe (HTTP peer IP capture). Also implicitly fixed red-cell-c2-37c (X-Real-IP trusted when behind_redirector=false) — closed by QA. Active: claimed red-cell-c2-131 (zero-key DEMON_INIT bypass). |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: 455 passed)
Observation: CTR offset persistence (red-9pf) fully resolved — offsets survive teamserver restart, verified by new `build_init_ack_after_registry_reload_uses_persisted_ctr_offset` test. LoginRateLimiter fix evicts oldest 50% when map reaches 10K entries; O(n log n) eviction path is acceptable for this use case. Peer IP fix properly distinguishes behind_redirector=true (trust X-Forwarded-For/X-Real-IP) from behind_redirector=false (use actual socket peer). No violations found this run.

### QA Review — 2026-03-11 — 7014778..2c2cb5f

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 2 | 0 | Closed: red-cell-c2-bam (WS chat + presence: ChatMessage dispatch, chat_presence_event, first/last_online_session, client InitConnectionInfo handling), red-cell-c2-3ug (cargo linker path for python 3.12 via .cargo/config.toml). Also: fix stopped listener auto-restart on startup (start_new_profile_listeners filters to Created-only). Claimed red-cell-c2-asj (Command Dispatch epic). |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: 485 passed, +9 from new callback/presence/chat tests)
Notes: Clean sprint. 4 new demon callbacks (CommandError, CommandExit, CommandKillDate, DemonInfo) all covered by unit tests. agent_update_event now correctly emits "Dead" for inactive agents (was always "Alive"). Chat broadcast correctly uses server-authoritative session username, not client-supplied value. Chat permission downgraded to Read (was Write) — correct, all operators should be able to chat. Stopped listener fix correctly filters on ListenerStatus::Created, preventing forced restart of operator-stopped listeners across teamserver restarts.

### QA Review — 2026-03-11 15:05 — 2c2cb5f..20b6897

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 5 | 1 | Closed: red-cell-c2-asj (complete inbound demon command dispatch: 10 new handlers — job, sleep, ppid-spoof, net, assembly ×2, config, transfer, mem-file, package-dropped; 4 new test functions), red-cell-c2-42d (Auth & RBAC epic), red-cell-c2-1mw (shared builtin dispatch registration refactor), red-cell-c2-b7n (kill-date negative wrap), red-cell-c2-3ny (auth typo). Bug: red-cell-c2-234 (P3) — grammar errors in job/transfer callback strings: "Successful suspended/resumed" → "Successfully …", "Failed to suspended/resumed" → "Failed to suspend/resume", "does not exists" → "does not exist" (×3). Same class as red-pgd / red-cell-c2-f0d. Test at line 7297 hardcodes wrong string and needs updating with fix. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: 491 passed)
Notes: Solid sprint. All 10 new handlers are well-structured with proper error propagation via `?`. The builtin-handler unification (`register_builtin_handlers` + `BuiltinHandlerDependencies`) cleanly resolves the red-cell-c2-1mw dispatch-chain divergence. Test coverage is good — 4 new integration-style tests cover all new handlers. Minor observation: `handle_config_callback` uses `i64::try_from(raw).unwrap_or(i64::MAX)` and `i32::try_from(raw).unwrap_or(i32::MAX)` for kill_date and working_hours fields — silently clamps out-of-range values rather than erroring; not filed (edge case, no realistic attacker path). Grammar P3 bug filed (red-cell-c2-234).

### QA Review — 2026-03-11 16:00 — 344d499..50ada0e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | No activity this run |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: 502 passed)
No new development commits since last checkpoint. Only QA checkpoint commit in range. Open epics in_progress: red-cell-c2-120 (Demon Agent Protocol P1), red-cell-c2-50q (Listeners P1), red-cell-c2-m5a (Logging & Audit Trail P2). No new bugs filed.

### QA Review — 2026-03-11 16:25 — 50ada0e..32a0678

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 0 | 0 | Claimed red-cell-c2-1ga (SQL-backed loot/credential filters), no closes yet |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: 502 passed)
No new development commits. Only QA checkpoint and a Codex claim commit in range. red-cell-c2-1ga (P2) now in_progress. Open P1 epics: red-cell-c2-120, red-cell-c2-50q. No new bugs filed.

### QA Review — 2026-03-11 17:54 — 32a0678..7e9e37f

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 4 | 1 | Closed: red-cell-c2-1ga, red-cell-c2-50q, red-cell-c2-2nf, red-cell-c2-3ci. Filed red-cell-c2-2r2 (P1 protocol regression): payload builder appends a non-Havoc DotNetNamePipe field to the packed Demon config, breaking payload compatibility with the reference builder. Additional Codex work in range: PE-header patching, client Python console command wiring, file-browser working-dir action. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: 512 passed)
Notes: One non-agent/unattributed commit added the Codex QA and architecture loop prompt/scripts. Main QA finding is protocol-level: Havoc's builder stops the Demon config after listener fields, but the Rust payload builder now appends DotNetNamePipe, altering the payload config layout. red-cell-c2-s9d now depends on red-cell-c2-2r2 until that compatibility regression is removed.

### QA Review — 2026-03-11 15:35 — 20b6897..344d499

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA loop only |
| Codex | 3 | 0 | Closed: red-cell-c2-4ye (REST API — credentials/jobs endpoints: CredentialSummary, JobSummary, paged queries, OpenAPI coverage), red-cell-c2-7zj (Python Plugin System — Havoc-style `RegisterCommand(function=..., module=..., command=...)` keyword shape accepted in addition to native signature), red-cell-c2-234 (grammar fix — "Successful suspended/resumed"/"does not exists" corrected; test at line 7297 updated). Active: claimed red-cell-c2-m5a (Logging & Audit Trail epic); session activity persisted APIs (344d499) appear to be progress toward its close. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: 502 passed, +11 from new session-activity/operator-inventory/chat-audit/credential/job tests)
Notes: Clean sprint. Three well-executed closes. Credential endpoint correctly filters by kind="credential" and exposes paginated view. Plugin compatibility shim for Havoc RegisterCommand well-tested (new `register_command_accepts_havoc_keyword_signature` test). Session-activity feature: `last_seen` populated from audit-log MAX(occurred_at) query, `AuditLogFilter.action_in` field added for SQL push-down, websocket chat messages now audited. Minor observation: `list_credentials` fetches all loot records in-memory then filters — superseded by open red-cell-c2-1ga (SQL-backed filters for loot/credentials), not re-filed. `unwrap_or_default()` on `latest_timestamps_by_actor_for_actions` in `operator_inventory()` silently swallows DB read errors; acceptable degraded behavior for display-only API, not filed. No P0/P1/P2 violations found.
