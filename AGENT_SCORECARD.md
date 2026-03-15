# Agent Scorecard

Maintained automatically by the QA and architecture review loops.
Each loop run updates the running totals and appends a review entry.

---

## Running Totals

| Metric | Claude | Codex | Cursor |
|--------|-------:|------:|-------:|
| Tasks closed | 113 | 181 | 31 |
| Bugs filed against | 10 | 28 | 9 |
| Bug rate (bugs/task) | 0.09 | 0.15 | 0.29 |
| Quality score | 91% | 85% | 71% |

## Violation Breakdown

| Violation type | Claude | Codex | Cursor |
|----------------|-------:|------:|-------:|
| unwrap / expect in production | 0 | 0 | 0 |
| Missing tests | 8 | 11 | 5 |
| Clippy warnings | 0 | 0 | 1 |
| Protocol errors | 5 | 22 | 3 |
| Security issues | 9 | 31 | 0 |
| Architecture drift | 2 | 21 | 0 |
| Memory / resource leaks | 0 | 10 | 1 |
| Startup / lifecycle regressions | 0 | 8 | 0 |
| Audit attribution errors | 0 | 1 | 0 |
| Availability / timeout regressions | 1 | 4 | 0 |
| Correctness / pagination | 4 | 2 | 1 |
| Workflow / close-hygiene | 3 | 0 | 0 |
| Code reuse / duplication | 3 | 0 | 0 |

---

## Review Log

<!-- QA and arch loops append entries below this line -->

### QA Review — 2026-03-15 13:35 — 762c867..2cb596e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 2 | Closed `red-cell-c2-a55z` (P1 security: magic pre-check before body buffering — `collect_body_with_magic_precheck()` rejects non-Demon traffic after first 8 bytes, 5 tests added); `red-cell-c2-wey1` (P2 completeness: agent.registered/agent.checkin/agent.dead audit events wired at correct lifecycle points, 3 integration tests); `red-cell-c2-rcy6` (P2 correctness: MZ+PE signature validation in `patch_payload()` before any byte writes, 3 tests). Filed `red-cell-c2-44as` (P3): `handle_checkin` writes audit log inline on hot callback path — should be `tokio::spawn` like `agent.dead`. Filed `red-cell-c2-wd91` (P4): `sweep_records_agent_dead_audit_entry` test uses two `yield_now()` to await background task — may be flaky on loaded CI. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (693 tests, 0 failures)
Notes: All three deliverables are high quality. The magic pre-check fix is well-designed and correctly documented. The audit lifecycle coverage is comprehensive. Two minor follow-on issues filed (hot-path sync write, test fragility).

### QA Review — 2026-03-15 11:00 — 0034f46..762c867

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 2 | Closed `red-cell-c2-dbve` (CTR desync fix: split decrypt into without-advancing + explicit advance_ctr_for_agent, deferred until parse succeeds; comprehensive test including adversary simulation); `red-cell-c2-cqmk` (plugin callback surface expanded: AgentRegistered, AgentDead, LootCaptured, TaskCreated — all four wired to correct lifecycle points with unit tests). Filed `red-cell-c2-mcm8` (P4): unnecessary `job.clone()` in `execute_agent_task` — enqueue takes the clone, plugin borrows original; reorder to emit-first and move job into enqueue. Filed `red-cell-c2-irhw` (P3): no wiring tests for `emit_agent_registered` (listeners.rs DemonInit path) or `emit_task_created` (websocket.rs execute_agent_task path); direct plugin unit tests exist but integration wiring is untested. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (675 tests, 0 failures)
Notes: Both deliverables are high quality. The CTR fix is the correct defense-in-depth fix for the desync attack and includes an end-to-end adversary simulation test. The plugin expansion is clean and complete. Two minor follow-on issues filed.

### Arch Review — 2026-03-15 16:00

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 5 | Security (2), Protocol (1), Docs (1), Maintainability (1) | red-cell-c2-dbve: CTR desync attack — garbage callback advances offset before parse succeeds, permanently breaking session (P1); red-cell-c2-a55z: 30 MiB body buffered pre-magic-check, memory DoS via concurrent connections (P1); red-cell-c2-t6dz: reconnect ack encrypted without advancing offset — post-reconnect callback path has no end-to-end test and protocol intent undocumented (P2); red-cell-c2-bp5w: crypto.rs module comment states CTR resets to 0 per message but production code uses advancing offsets (P3); red-cell-c2-ime3: dispatch.rs at 9 800 lines, split into per-command-family modules (P3) |
| Codex | 0 | — | No new findings attributed |
| Cursor | 0 | — | No new findings attributed |

Overall codebase health: on track
Biggest blindspot: CTR desync attack (red-cell-c2-dbve) — an adversary knowing any active agent_id (visible in plaintext packet headers) can permanently break that agent's session by sending a crafted packet with valid magic and garbage payload. No rate limiter covers callbacks and the CTR offset advances before protocol parsing succeeds.

### QA Review — 2026-03-15 14:15 — 1105dc2..897414b

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 1 | Closed `red-cell-c2-l2vk` (Profile::from_file now asserts path in ProfileError::Read via tempfile::TempDir), `red-cell-c2-24yz` (two AES-256-CTR reference vector tests at block_offset=2 pinned against independent Python reference; also reordered duplicate test in domain.rs), `red-cell-c2-37xa` (TLS cert-present/key-missing error path test). All changes are test-only — no production code touched. Filed `red-cell-c2-olwt` (P2): agent loop re-claims already in_progress issues on restart, generating 28 redundant claim commits for 14 issues in this range. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` (607 tests, 0 failures)
Notes: 14 issues remain stuck in_progress (wf2d, mut8, s3a9, 1x9h, 2u74, 3bdz, 2qfs, 3inc, 11aj, 2tru, 35k0, 3uhe, 2z11, 2h4n) — agent is claiming but not completing within a loop run. Workflow bug `red-cell-c2-olwt` filed for duplicate claim pattern.

### QA Review — 2026-03-15 14:00 — 8c78eac..1105dc2

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 7 | 0 | Closed `red-cell-c2-7thi` (tighter zero-sleep liveness assertions: assert_eq sweep_interval==1s, timeout_for(0)==3); `red-cell-c2-2rw7` (mixed-liveness sweep test: 2 stale + 1 fresh, asserts sort order and fresh remains active); `red-cell-c2-w0g0` (webhook shutdown returns true immediately when disabled); `red-cell-c2-1w6q` (route smoke tests: /api/v1→200, /havoc→non-404; extracted build_test_state() helper); `red-cell-c2-3vns` (DNS listener validation: all 3 error paths tested); `red-cell-c2-2j3l` (bool deserializer rejects "yes"/"maybe" strings); `red-cell-c2-iiif` (deserialize_agent_id rejects 2^32 and u64::MAX with "does not fit in u32"). No defects found — all changes are test additions only. |
| Codex | 0 | 0 | No activity in range. |
| Cursor | 0 | 0 | No activity in range. |

Build: **passed** — `cargo check`, `cargo clippy -- -D warnings`, `cargo test --workspace` (600+ tests, 0 failures)

### QA Review — 2026-03-15 12:30 — e9e4f38..828dbe7

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 5 | 0 | Closed `red-cell-c2-a74c` (refuse CHECKIN key rotation entirely — was previously allowed for direct agents, now refused universally; tests updated to verify original key preserved and CTR offset not reset); `red-cell-c2-3hro` (MAX_JOB_QUEUE_DEPTH=1000 cap + QueueFull error + tests); `red-cell-c2-2n8o` (constant-time session token lookup via linear scan + `subtle::ConstantTimeEq`; 3 regression tests added); `red-cell-c2-3uhw` (workflow close-hygiene process chore); `red-cell-c2-3cp1` (3 direct handler tests for `websocket_handler`: lifecycle, malformed-frame, oversized-pre-auth). No new defects found. |
| Codex | 0 | 0 | No activity in range. |
| Cursor | 0 | 0 | No activity in range. |

Build: **passed** — `cargo check`, `cargo clippy -- -D warnings`, `cargo test --workspace` (539+ tests, 0 failures)

### Arch Review — 2026-03-15 06:00

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 11 | Security (2), Missing tests (5), Correctness (3), Arch drift (1) | red-cell-c2-zroy: TLS private key not wrapped in Zeroizing<>; red-cell-c2-j8a0: API key HMAC secret from UUIDv4 (244 vs 256 bits entropy); red-cell-c2-5rtk: DEFAULT_MAX_DOWNLOAD_BYTES defined twice with different types; red-cell-c2-b44y: all-zero key/IV validation duplicated in demon.rs and dispatch.rs; red-cell-c2-0ff3: HTTP method burned into payload not validated against listener config; red-cell-c2-wey1: audit log missing agent lifecycle events (registration, death, checkin); red-cell-c2-kky2: no test verifying SOCKS5 binds only to localhost; red-cell-c2-o7z6: no test for X-Forwarded-For spoofing prevention; red-cell-c2-m8tz: no test for concurrent DemonInit at agent cap; red-cell-c2-a0oo: no test verifying QueueFull at MAX_JOB_QUEUE_DEPTH; red-cell-c2-h5a3: no test for CTR offset persistence/recovery after restart |
| Codex | 4 | Correctness (2), Arch drift (2) | red-cell-c2-2hd9: DemonInitRateLimiter and LoginRateLimiter duplicate eviction logic verbatim; red-cell-c2-yh94: DEMON_MAX_RESPONSE_LENGTH and MAX_AGENT_REQUEST_BODY_LEN same cap in two places; red-cell-c2-cqmk: plugin API only exposes emit_agent_checkin, all other lifecycle hooks absent; red-cell-c2-rcy6: patch_payload() writes PE fields without validating MZ magic first |
| Cursor | 0 | — | No new findings attributed |

Overall codebase health: on track
Biggest blindspot: CTR offset continuity after restart — persist-before-mutate ordering is correct but there is no test that exercises the full save/reload/encrypt cycle, leaving keystream collision (two-time-pad) after restart as an unverified regression risk.

### Arch Review — 2026-03-14 (fresh-eyes run)

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 1 | Security | red-cell-c2-8ugx: AES-256-CTR keystream reused per-message (two-time-pad), crypto.rs |
| Codex | 16 | Security (6), Protocol (4), Missing tests (4), Arch drift (2), Resource (1) | red-cell-c2-ude5: all-zero IV accepted in DemonInit; red-cell-c2-bhvi: AES key not zeroized in memory; red-cell-c2-n950: DUMMY_PASSWORD_HASH not valid Argon2 PHC (user enum timing); red-cell-c2-35d7: build_tls_config ignores profile cert; red-cell-c2-mvcp: payload -D defines not sanitized; red-cell-c2-2me2: webhook shutdown race; red-cell-c2-q9re: API key auth not rate-limited; red-cell-c2-er7d: DNS listener absent; red-cell-c2-235t: DemonEnvelope underflow on <4 bytes; red-cell-c2-5q73: process_path aliased to process_name; red-cell-c2-lqzt: os_build always empty; red-cell-c2-xfkr: pivot list handler no-op; red-cell-c2-heg7: no RBAC WebSocket enforcement test; red-cell-c2-ipj0: havoc_compat test silently skips; red-cell-c2-5yg3: all-zero IV test missing; red-cell-c2-z3xc: LoginRateLimiter lockout untested; red-cell-c2-tyx1: listener stop errors discarded |
| Cursor | 0 | — | No new findings attributed |

Overall codebase health: drifting
Biggest blindspot: Agent AES key material (both key and IV) is never zeroized and lives in heap simultaneously in base64 and decoded forms. Combined with per-message keystream reuse at offset 0, a teamserver memory dump would expose all agent communication keys and allow retroactive decryption of recorded traffic.

### Arch Review — 2026-03-13 14:16

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 1 | Security issues | red-cell-c2-bfih: COMMAND_CHECKIN missing all-zero IV rejection and test (P1) |
| Codex | 5 | Security issues, Memory/resource leaks, Missing tests | red-cell-c2-3qq0: DEMON_INIT no all-zero IV check (P1); red-cell-c2-2n8o: session token lookup timing oracle (P2); red-cell-c2-3hro: unbounded per-agent job queue (P2); red-cell-c2-a74c: CHECKIN key rotation no freshness guarantee (P2); red-cell-c2-2lyr: axum::serve errors silently swallowed in webhook/audit helpers (P3) |
| Cursor | 0 | — | No new findings attributed |

Overall codebase health: drifting
Biggest blindspot: AES IV is still not validated for the all-zero case in either DEMON_INIT or COMMAND_CHECKIN, and the per-agent job queue has no depth cap — both are trivially exploitable by a compromised agent or operator.

### QA Review — 2026-03-13 13:53 — f6c7d35..446ae04

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed `red-cell-c2-30fe` — `validate_checkin_transport_material` correctly rejects all-zero AES key before state mutation; regression test asserts state immutability, CTR offset preservation, no event broadcast. `red-cell-c2-16w0` (test-blocker) also resolved as a side-effect. Workflow violation noted (process issue `red-cell-c2-3uhw` filed, P4): issue was not formally closed at session end. |
| Codex | 0 | 0 | Nine claim commits only (`red-cell-c2-33iq`, `red-cell-c2-355s`, `red-cell-c2-2f9l`, `red-cell-c2-3j7w`, `red-cell-c2-2f75`, `red-cell-c2-13qu`, `red-cell-c2-13oi`, `red-cell-c2-101f`). No code changes in range; all remain `in_progress`. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check`, `cargo clippy -- -D warnings`, `cargo test --workspace` (459 tests, 0 failures)

### QA Review — 2026-03-13 12:49 — 7f7b888..f6c7d35

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity in reviewed commits. |
| Codex | 6 | 0 | Closed `red-cell-c2-1sru`, `red-cell-c2-2yjs`, `red-cell-c2-y8fp`, `red-cell-c2-1rb2`, `red-cell-c2-1xly`, and `red-cell-c2-2b41`. One additional claim commit (`red-cell-c2-30fe`) matches the only active `in_progress` issue. Reviewed Rust changes are a payload-builder workspace-root fix plus targeted test additions; no new committed defects found. |
| Cursor | 0 | 0 | No activity in reviewed commits. |

Build: **partial** — `cargo check --workspace` passed in the current tree. `cargo clippy --workspace -- -D warnings` and `cargo test --workspace` fail in the dirty local worktree because an unstaged edit in `teamserver/src/dispatch.rs` references `AGENT_KEY_LENGTH` without importing it; that change is not part of the reviewed commit range.

### Arch Review — 2026-03-13 12:44

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No new agent-attributed findings |
| Codex | 0 | — | No new agent-attributed findings |
| Cursor | 0 | — | No new agent-attributed findings |

Overall codebase health: drifting
Biggest blindspot: protocol and control-surface completeness still have misleading green paths — malformed `COMMAND_CHECKIN` packets can be treated as success, pivot child sessions lose listener provenance, and the published Service/External surfaces still advertise capabilities the runtime does not actually provide.

Additional findings filed this run were attributed to Michel Klomp: `red-cell-c2-3ntq`, `red-cell-c2-smdw`, `red-cell-c2-30fe`, `red-cell-c2-21if`, and `red-cell-c2-35jc`.

### QA Review — 2026-03-13 12:21 — ce9f784..7f7b888

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity in reviewed commits. |
| Codex | 4 | 1 | Closed `red-cell-c2-x86m` (AgentInfo name collision), `red-cell-c2-1b5d` (logging init tracing coverage), `red-cell-c2-2hud` (payload builder constructor coverage), and `red-cell-c2-1q7c` (PluginRuntime state accessor coverage). Filed `red-cell-c2-1rb2` because the new payload-builder coverage does not exercise the public `PayloadBuilderService::from_profile`, leaving the production repo-root resolution bug undetected. |
| Cursor | 0 | 0 | No activity in reviewed commits. |

Build: **passed** — clean worktree verification at `7f7b888` passed `cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace` (756 tests, 0 failures).

### QA Review — 2026-03-13 11:51 — 0168b03..ce9f784

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No implementation closes in range. Follow-up review/task commits only (`chore(qa)` and `chore(test-review)`). |
| Codex | 3 | 0 | Closed `red-cell-c2-1hlw` (credential-line false positive fix), `red-cell-c2-1ob9` (credential extraction heuristic tests), and `red-cell-c2-2maa` (operator WebSocket max message size cap). Also claimed `red-cell-c2-x86m`, but no committed fix for it landed in this range. No defects found in the reviewed commits. |
| Cursor | 0 | 0 | No activity in reviewed commits. |

Build: **passed** — clean detached-worktree verification at `ce9f784` passed `cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace` (745 tests, 0 failures).

### QA Review — 2026-03-13 10:20 — dda87b9..51f4ef2

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA/arch review runs only — no implementation commits. |
| Codex | 3 | 0 | Closed `red-cell-c2-ktpf` (reject overflow kill_date — beads-only close, code landed prior), `red-cell-c2-1e2s` (fix `SocksServerHandle::port()` error propagation — no silent `unwrap_or(0)`, returns `Result`; callers updated; 2 tests added), `red-cell-c2-2puf` (AES-CTR rotation test — verifies CTR offset resets to 0 after CHECKIN, post-rotation ciphertext uses new key at block 0, comprehensive round-trip checks). No defects found. |
| Cursor | 0 | 0 | No activity in reviewed commits. |

Build: **passed** — `cargo check`, `cargo clippy -D warnings`, and `cargo test` all pass cleanly. 490 tests total across all crates, 0 failures.

### Arch Review — 2026-03-13 10:05

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No new agent-attributed findings |
| Codex | 3 | Security issues, Architecture drift | red-cell-c2-23zy: invalid REST API keys bypass rate limiting; red-cell-c2-jowu: `AgentRegistry` transport setters mutate memory before SQLite commit; red-cell-c2-2qvk: teamserver control-plane TLS cert rotates every restart |
| Cursor | 0 | — | No new agent-attributed findings |

Overall codebase health: drifting
Biggest blindspot: control-plane hardening still breaks down on non-happy paths — invalid API authentication is unthrottled, transport state setters are not persistence-safe on write failure, and the teamserver still lacks a durable TLS identity for the operator channel.

### QA Review — 2026-03-13 10:00 — 8b18663..9b8c68e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity in reviewed commits. |
| Codex | 4 | 0 | Closed `red-cell-c2-1vsm` (3 unit tests for `AgentRegistry::disconnect_link` — removes parent/child relationships, no-op on missing link, cleanup hook fires), `red-cell-c2-1utu` (3 tests for `json_error_response` — status preservation, field serialization, punctuation passthrough), `red-cell-c2-3581` (tests for operator metadata: `as_operator_info` wire fields, unusual usernames, offline operator without last_seen), `red-cell-c2-2tjr` (3 integration tests for `AgentRepository` listener-bound helpers — persist+reload, missing-agent error paths, connect_with_options migration). Also notable: database.rs got correct `rows_affected() == 0` guards in `update_with_listener`, `set_note`, `update_agent_ctr_block_offset`. No defects found. |
| Cursor | 0 | 0 | No activity in reviewed commits. |

Build: **passed** — `cargo check`, `cargo clippy -D warnings`, and `cargo test` all pass cleanly. 736 tests total, 0 failures.

### Arch Review — 2026-03-13 09:45

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 1 | Security issues | red-cell-c2-1xzi: DNS download handler allows unauthenticated response queue depletion (P2 security) |
| Codex | 1 | Protocol errors | red-cell-c2-3giq: CHECKIN key-rotation accepted without replay/freshness protection (P2 security) |
| Cursor | 1 | Correctness / pagination | red-cell-c2-xbjh: query_session_activity inverts count/query order and leaves redundant in-memory filter (P3 quality) |

Overall codebase health: drifting
Biggest blindspot: the DNS C2 download endpoint (`handle_download`) has no authentication gate — an adversary who observes the C2 domain and any agent ID from DNS traffic can silently deplete queued task responses by sending a single crafted TXT query, causing the real agent to lose its next instruction without any error logged on either side.

### QA Review — 2026-03-13 09:45 — e86a3d4..8b18663

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | Filed 5 test-gap issues via test-review scan (red-cell-c2-13su, red-cell-c2-1dbh, red-cell-c2-24tg, red-cell-c2-8s5p, red-cell-c2-zzsx). Not attributed as agent defects. |
| Codex | 4 | 0 | Closed `red-cell-c2-3cve` (remove dead `max_download_bytes` param chain — clean refactor across 7 call sites in listeners.rs), `red-cell-c2-3oq5` (bound socket lifecycle test with 5s timeout in dispatch.rs), `red-cell-c2-8djk` (3 unit tests for `install_default_crypto_provider` idempotency/ordering in tls.rs), `red-cell-c2-1gag` (3 tests for `spawn_agent_liveness_monitor`: startup/shutdown, aggressive timing, stale-agent cleanup side-effects). All work is solid — no defects found. |
| Cursor | 0 | 0 | No activity in reviewed commits. |

Build: **passed** — `cargo check`, `cargo clippy -D warnings`, and `cargo test` all pass cleanly. 113 library tests + 3 integration tests, 0 failures.

### QA Review — 2026-03-13 09:30 — b327128..e86a3d4

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed `red-cell-c2-2z9d`; added public-API unit tests for `local_config` `save()`/`load()` round-trip, invalid TOML fallback, and save-no-panic. Tests use a mutex to avoid races on the shared platform config path and correctly restore the original file. No defects found. |
| Codex | 3 | 0 | Closed `red-cell-c2-320o` (`DemonPackage::encoded_len` unit tests — empty, non-empty, large payload+message aggregation), `red-cell-c2-87h2` (common public API smoke tests — ListenerConfig round-trip, CommonError variants, compile-without-private-paths), `red-cell-c2-3htr` (client login persistence integration tests — round-trip, malformed-config fallback, optional TLS fields). All tests are well-scoped, use tempdir isolation, and pass cleanly. |
| Cursor | 0 | 0 | No activity in reviewed commits. |

Build: **partial** — `red-cell-client` + `red-cell-common` pass all tests (113+ tests, 0 failed). Teamserver fails to compile due to pre-existing arity mismatch in `listeners.rs` (tracked as `red-cell-c2-3cve`, in-progress by Codex).

### Arch Review — 2026-03-13 07:45

| Agent | Findings | Categories | Notes |
|-------|---------:|------------|-------|
| Claude | 0 | — | No new agent-attributed findings |
| Codex | 0 | — | No new agent-attributed findings |
| Cursor | 0 | — | No new agent-attributed findings |

3 new findings filed, all attributed to Michel Klomp (repo owner): red-cell-c2-2f9l (unknown agent callback not recorded in audit log, P2 security), red-cell-c2-355s (API key digest lookup is not constant-time, P2 security), red-cell-c2-33iq (per-agent job queue has no size cap, P2 resource). No AI agent violations this run.

Overall codebase health: drifting
Biggest blindspot: unknown agent callbacks reach the listener without any audit record — a probe loop against an HTTP or DNS listener with random agent IDs is forensically invisible, unlike unknown reconnect probes which do write to the audit log.

Build: passed (679 total tests, 0 failures, 0 clippy warnings)

### QA Review — 2026-03-12 16:45 — fd0ab71..942cc1f

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | One prior QA checkpoint commit in range only. |
| Codex | 1 | 0 | Closed red-cell-c2-1qr5 with RBAC session-token extractor edge-case tests in `teamserver/src/rbac.rs`; one additional claim commit (`red-cell-c2-3b1j`) correctly set the issue to `in_progress` in JSONL. No code defects found in the reviewed diff. |
| Cursor | 0 | 0 | — |

Build: skipped (`cargo check --workspace` passed; `cargo clippy --workspace -- -D warnings` and `cargo test --workspace` were blocked by concurrent local cargo locks during this review)

### QA Review — 2026-03-12 15:38 — 863aba6..2ddfd85

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | — |
| Codex | 5 | 0 | Closed red-cell-c2-w3ac (logging config fallback; code reviewed previously), red-cell-c2-35r8 (event bus zero-history mode fix + tests), red-cell-c2-t2kg (payload builder HTTP/DNS edge-case tests), red-cell-c2-33vi (dispatch unknown-agent checkin path), red-cell-c2-maah (webhook non-2xx test coverage). No issues found. |
| Cursor | 0 | 0 | — |

Build: passed (407 teamserver + 104 common lib tests, 0 failures, 0 clippy warnings)

### QA Review — 2026-03-12 15:07 — a7cec53..d4d6017

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | — |
| Codex | 3 | 2 | Closed red-cell-c2-pbmw (DownloadTracker memory leak), red-cell-c2-34ij (proxy_password exposure), red-cell-c2-3lpa (socket callback subcommand coverage). New bugs: red-cell-c2-3cve (dead _max_download_bytes parameter chain, P3), red-cell-c2-3oq5 (unbounded spin loop in SOCKS integration test, P3). |
| Cursor | 0 | 0 | — |

Build: passed (104 tests, 0 failures, 0 clippy warnings)

### QA Review — 2026-03-12 15:00 — 93c9947..a7cec53

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | — |
| Codex | 4 | 0 | Closed red-cell-c2-2i18 (TLS error path tests), red-cell-c2-24pm (liveness sweep guard tests), red-cell-c2-3q5x (SessionActivityRecord conversion failures), red-cell-c2-2haq (alive branch test coverage). Clean refactor of mark_stale_agent_if_unchanged. |
| Cursor | 0 | 0 | — |

Build: passed (104 tests, 0 failures, 0 clippy warnings)

### QA Review — 2026-03-12 14:13 — ff94f05..508eef5

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed red-cell-c2-1e81 (BufferTooShort edge-case tests), red-cell-c2-16vk (crypto uniqueness/CTR overflow tests) |
| Codex | 5 | 0 | Closed red-cell-c2-3bxx (local config fallbacks), red-cell-c2-2lf7 (working_hours bitmask fix), red-cell-c2-16sh (unknown agent REST 404s), red-cell-c2-pwc3 (single-item credential/loot endpoints), red-cell-c2-27pb (create_operator validation error paths). QA also closed red-cell-c2-16io (same fix as 2lf7, not closed by Codex). |
| Cursor | 0 | 0 | — |

Build: passed (100 tests, 0 failures, 0 clippy warnings)

### QA Review — 2026-03-12 — f39a3a..156b8e1

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 0 | Closed red-cell-c2-ewin (Profile error-path tests), red-cell-c2-kn1w (normalize_server_url error-path tests), red-cell-c2-2jf8 (Argon2 test cache fix) |
| Codex | 0 | 0 | — |
| Cursor | 0 | 0 | — |

Build: passed (95 tests, 0 failures, 0 clippy warnings)

### Arch Review — 2026-03-12 11:29

| Agent | Findings | Categories | Notes |
|-------|---------:|------------|-------|
| Claude | 0 | — | No new agent-attributed findings this run |
| Codex | 1 | Security issues | Filed red-cell-c2-34ij |
| Cursor | 0 | — | No new agent-attributed findings this run |

Overall codebase health: drifting
Biggest blindspot: proxy credentials (`proxy_password`) are included in the `ListenerInfo` wire format sent to all authenticated WebSocket operators regardless of RBAC role — Analyst-role operators receive credentials they should never see. The gap stems from `to_operator_info()` in listeners.rs having no field-level redaction layer and no role-aware serialisation path in `send_session_snapshot()`.

### Arch Review — 2026-03-12 14:32

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No new agent-attributed findings |
| Codex | 3 | Protocol errors, Architecture drift, Missing tests | Filed red-cell-c2-2njj, red-cell-c2-2aec, red-cell-c2-vwrf |
| Cursor | 0 | — | No new agent-attributed findings |

Overall codebase health: drifting
Biggest blindspot: `kill_date` is read as a u64 from the Demon INIT payload but silently clamped to `i64::MAX` on overflow (red-cell-c2-2njj). An implant with a corrupted or intentionally-crafted kill_date field would be registered with an effectively infinite kill date, defeating an OPSEC control. No test exercises the overflow path.

### Arch Review — 2026-03-12 09:53

| Agent | Findings | Categories | Notes |
|-------|---------:|------------|-------|
| Claude | 0 | — | No new agent-attributed findings this run |
| Codex | 3 | Protocol errors, Security issues | Filed red-cell-c2-2x0k, red-cell-c2-25uh, red-cell-c2-s7rj |
| Cursor | 0 | — | No new agent-attributed findings this run |

Overall codebase health: drifting
Biggest blindspot: COMMAND_CHECKIN completely ignores the Havoc session-key refresh and metadata update (red-cell-c2-14fa) — real Demon agents will desync their AES-CTR keystreams on the first CHECKIN after a reconnect, breaking all subsequent callbacks silently rather than with a visible error.

### Arch Review — 2026-03-12 07:08

| Agent | Findings | Categories | Notes |
|-------|---------:|------------|-------|
| Claude | 0 | — | No new agent-attributed findings this run |
| Codex | 2 | Startup / lifecycle regressions, Architecture drift | Filed red-cell-c2-3ath and red-cell-c2-15rj |
| Cursor | 0 | — | No new agent-attributed findings this run |

Overall codebase health: drifting
Biggest blindspot: listener edge paths still look healthier than they are because the green suite mostly exercises controlled startup and request flows, not hostile proxy/header chains or sustained listener pressure.
Additional findings filed this run were attributed to Michel Klomp: red-cell-c2-31w8 and red-cell-c2-4row.

### Arch Review — 2026-03-12 06:07

| Agent | Findings | Categories | Notes |
|-------|---------:|------------|-------|
| Claude | 0 | — | No new agent-attributed findings this run |
| Codex | 5 | Protocol errors, Security issues, Memory / resource leaks, Architecture drift | Filed red-cell-c2-14fa, red-cell-c2-1t80, red-cell-c2-q2n1, red-cell-c2-21yh, and red-cell-c2-uenz |
| Cursor | 0 | — | No new agent-attributed findings this run |

Overall codebase health: drifting
Biggest blindspot: alternate Demon paths and advertised transport surfaces are still under-tested end to end, so callback variants like metadata-bearing COMMAND_CHECKIN and declared listener types can remain broken while the main happy-path suite stays green.

### Arch Review — 2026-03-12 04:06

| Agent | Findings | Categories | Notes |
|-------|---------:|------------|-------|
| Claude | 0 | — | No new agent-attributed findings this run |
| Codex | 3 | Security issues, Protocol errors, Architecture drift | Filed red-cell-c2-3rqy, red-cell-c2-1auz, and red-cell-c2-pu5a |
| Cursor | 0 | — | No new agent-attributed findings this run |

Overall codebase health: drifting
Biggest blindspot: protocol-compatibility checks still focus on Red Cell's current Rust behavior, so config-path and HTTP reply-path mismatches against Havoc can stay green until an operator uses those features against a real Demon workflow.

### QA Review — 2026-03-12 04:35 — 7a16e6b..50e48a4

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 0 | 0 | No development commits in range; reviewed one prior QA bookkeeping commit only |
| Cursor | 0 | 0 | No activity this run |

Build: passed (`cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace`)
Notes: Reviewed one commit from `7a16e6b` to `50e48a4`. The diff only advanced `.beads/qa_checkpoint` and appended a scorecard entry; no Rust, config, or protocol code changed. No new QA bugs were filed. `br list --status=open` and `br ready` returned `database is busy` during this run, but `br list --status=in_progress` succeeded and there was no conflicting agent activity to investigate.

### QA Review — 2026-03-12 04:12 — 86b3c1e..7a16e6b

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 5 | 0 | Closed: red-2ne, red-2d4, red-3nf, red-mwx, red-rts. Remaining activity in range was claim bookkeeping plus one startup-cap fix and two regression-test additions. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (`cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace`)
Notes: Reviewed thirty-six commits from `86b3c1e` to `7a16e6b`. The registry-cap startup fix in [teamserver/src/agents.rs](/home/michel/Red-Cell-C2/teamserver/src/agents.rs) and the new HTTP listener regression coverage in [teamserver/src/listeners.rs](/home/michel/Red-Cell-C2/teamserver/src/listeners.rs) and [teamserver/tests/http_listener_pipeline.rs](/home/michel/Red-Cell-C2/teamserver/tests/http_listener_pipeline.rs) look correct. No new QA bugs were filed. `br list --status=in_progress` and `br list --status=open` intermittently returned `database is busy`, but `br ready` succeeded and the reviewed closures matched implementation commits, so this run treats the lock as transient tooling contention rather than a repository defect.

### QA Review — 2026-03-12 01:09 — 98d3599..86b3c1e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 5 | 0 | Closed: red-aow, red-cell-c2-3bh1, red-1u6, red-2d3, red-sh4. Also added regression tests for restart-safe demon callback parsing and claimed red-rts. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (`cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace` on `86b3c1e`)
Notes: Reviewed sixteen commits from the checkpoint to current `HEAD`; agent-authored code changes were limited to targeted regression tests plus the listener-startup fix already filed in the prior QA run and now corrected. No new QA bugs were filed. `br` intermittently returned `database is busy`, but `br ready` succeeded and the only confirmed active in-progress issue (`red-rts`) has a matching fresh claim commit, so beads state does not appear stale.

### QA Review — 2026-03-12 00:29 — bb2c902..98d3599

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 6 | 1 | Closed: red-pgd, red-1d2, red-8o6, red-4vu, red-cell-c2-3rgl, red-cell-c2-26wc. Filed red-cell-c2-3bh1 because the external-listener startup fix now suppresses all `StartFailed` listener boot errors, not just unsupported External listeners. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (`cargo check`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace` on a clean `HEAD` archive; local worktree had unrelated uncommitted changes)
Notes: Reviewed seven non-QA commits in range. The websocket idle-auth timeout change looks correct and is covered by a regression test. The startup listener change regressed boot semantics by allowing real listener bind/init failures to be silently downgraded to Error state during fresh-profile startup.

### QA Review — 2026-03-12 00:03 — 806efaa..bb2c902

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA bookkeeping commit only |
| Codex | 2 | 1 | Closed: red-pkl, red-cell-c2-1m9l. Filed red-cell-c2-2nos for the new Havoc compatibility test's machine-specific path and implicit Go dependency. red-cell-c2-26wc is now in_progress with a matching claim commit. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check clean; cargo clippy --workspace -- -D warnings clean; cargo test --workspace passed, including the new `havoc_compatibility` integration test)
Notes: Reviewed seven commits in range. The AES-CTR rollback itself appears correct and is now validated against the checked-in Havoc reference, but the new regression test is not portable because it shells out to Go and hardcodes this workstation's checkout path. No stale in-progress items or unjustified task closures were found in beads state.

### Arch Review — 2026-03-11 23:36

| Agent | Findings | Categories | Notes |
|-------|---------:|------------|-------|
| Claude | 0 | — | No findings this run |
| Codex | 5 | Availability / timeout regressions, Startup / lifecycle regressions, Architecture drift, Protocol errors | Filed red-cell-c2-26wc, red-cell-c2-39z8, red-cell-c2-3rgl, red-cell-c2-33lj, red-cell-c2-pyct |
| Cursor | 1 | Protocol errors | Filed red-cell-c2-1m9l against the new AES-CTR offset model, which diverges from the checked-in Havoc reference implementation |

Overall codebase health: drifting
Biggest blindspot: protocol fidelity is being validated mostly against Red Cell's own mocks instead of the checked-in Havoc implementation, so wire-level incompatibilities can stay green in tests while breaking real Demon interoperability.

### Arch Review — 2026-03-11 20:34

| Agent | Findings | Categories | Notes |
|-------|---------:|------------|-------|
| Claude | 0 | — | No findings this run |
| Codex | 1 | Security issues, Protocol errors | Filed red-cell-c2-1uoh: existing DEMON_INIT can overwrite a registered agent session |
| Cursor | 0 | — | No findings this run |

Overall codebase health: drifting
Biggest blindspot: the operator WebSocket still bypasses structured audit logging for destructive mutations, and listener runtimes do not reconcile persisted state when their tasks die.
Additional findings filed this run were attributed to Michel Klomp: red-cell-c2-1cb1, red-cell-c2-34qy, and red-cell-c2-7369.

### Arch Review — 2026-03-11 19:08

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No findings this run |
| Codex | 4 | Architecture drift ×3, Protocol ×1 | red-cell-c2-36v7 (external/service bridge is a stub), red-cell-c2-1tfr (listener operator round-trip drops advanced fields), red-cell-c2-6gn9 (DNS listeners unsupported by payload builder), red-cell-c2-3djm (Discord webhook config is dead) |
| Cursor | 0 | — | No findings this run |

Overall codebase health: drifting
Biggest blindspot: feature surfaces are landing in config and listener state before the end-to-end workflows exist, so operators can start or edit transports that silently degrade or do nothing.

### Arch Review — 2026-03-11 16:58

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No findings this run |
| Codex | 4 | Security ×3, Architecture drift ×1 | red-cell-c2-1ja (agent AES keys leaked over WS/API), red-cell-c2-3qm (session token logged), red-cell-c2-2nk (spoofable redirector headers), red-cell-c2-166 (listener identity lost in snapshots) |
| Cursor | 0 | — | No findings this run |

Overall codebase health: drifting
Biggest blindspot: operator-facing state surfaces still expose or mishandle secrets — authenticated readers can recover per-agent transport keys, and the WebSocket auth path logs bearer tokens.

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

### QA Review — 2026-03-11 18:18 — 7e9e37f..f17173f

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity in reviewed development commits |
| Codex | 3 | 1 | Closed: red-cell-c2-2r2, red-cell-c2-1ja, red-cell-c2-3qm. Filed red-cell-c2-29bq (P1 protocol/compatibility regression): client Python command dispatch lowercases callback arguments and `CommandContext.command_line`. Additional Codex work in range: claimed red-cell-c2-2nk and added Havoc client Python compatibility shims. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: 515 passed)
Notes: Security fixes for agent crypto exposure and websocket token logging are correct. One new regression was introduced in the client Python compatibility layer: command matching is case-insensitive by lowercasing the entire operator input, which mutates argument payloads before scripts receive them. Non-agent commits in range: one prior QA checkpoint and one architecture-review bookkeeping commit.

### QA Review — 2026-03-11 18:41 — f17173f..3e67e3b

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity in reviewed development commits |
| Codex | 3 | 0 | Closed: red-cell-c2-2nk, red-cell-c2-29bq, red-cell-c2-166. All three fixes reviewed clean; no new QA issues filed. Active: claimed red-cell-c2-89o. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: workspace passed)
Notes: Reviewed the forwarded-IP trust hardening, Python command casing preservation, and listener-identity persistence changes. Build and tests are clean, migration for `listener_name` is backfilled safely with a non-null default, and no new protocol/security regressions were found in this range. `br` intermittently returned `database is busy` for one ready-list query during the review, but repeated reads succeeded and this appears to be a transient tooling lock rather than a repository defect.

### QA Review — 2026-03-11 19:04 — 3e67e3b..8bac71d

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 0 | 0 | No development commits in range; reviewed one prior QA bookkeeping commit only |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: workspace passed)
Notes: Review range contained no product-code changes, only the previous QA checkpoint/scorecard commit. No new QA bugs filed. `br list --status=open` intermittently returned `database is busy`, but repeated reads succeeded and `br ready` returned expected results; treated as a transient tooling lock, not a repository defect.

### QA Review — 2026-03-11 19:28 — 8bac71d..fa73426

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 2 | 1 | Closed: red-cell-c2-36v7, red-cell-c2-1tfr. Filed red-cell-c2-1exz (P1 startup/lifecycle regression: persisted external listener in Running state aborts teamserver startup on restart). red-cell-c2-6gn9 was claimed but not closed. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: workspace passed)
Notes: Reviewed the external-listener startup rejection and listener operator round-trip preservation changes in `crates/teamserver/src/listeners.rs`. One regression remains: `restore_running()` now propagates the new external-listener `StartFailed` path into `main`, so a persisted external listener marked Running can prevent the entire teamserver from booting after restart. `br list` still intermittently reports `database is busy`, but repeated reads and `br ready` succeeded; treated as a transient tooling lock, not a repository defect.

### QA Review — 2026-03-11 19:51 — fa73426..9690167

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 3 | 1 | Closed: red-cell-c2-6gn9, red-cell-c2-1exz, red-cell-c2-3djm. Filed red-cell-c2-x38n (P1 availability regression: synchronous audit webhook delivery can stall operator/API actions indefinitely). |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: workspace passed)
Notes: Reviewed DNS listener gating, persisted-listener restore handling, and Discord audit webhook delivery. The closed listener-restore issue is now covered by startup tests and appears fixed. One defect remains in the new webhook path: audit notifications are awaited inline with no request timeout, so a hung Discord endpoint can block operator login, chat, listener actions, and API tasking despite the notifier being documented as best-effort.

### QA Review — 2026-03-11 20:14 — 9690167..3901f58

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA/infra loop maintenance only |
| Codex | 1 | 0 | Closed red-cell-c2-x38n. Audit webhook delivery is now detached from the request path, bounded by a 5s client timeout, and covered by a stalled-webhook regression test. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: workspace passed)
Notes: Reviewed the follow-up fix for red-cell-c2-x38n in `crates/teamserver/src/audit.rs` and `crates/teamserver/src/webhook.rs`. The previous availability regression is resolved without introducing new build, clippy, or test failures. No new QA bugs filed in this range.

### QA Review — 2026-03-11 20:36 — 3901f58..c1eb030

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 0 | 0 | No activity this run |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: workspace passed)
Notes: Review range contained only QA/architecture bookkeeping commits authored by Michel Klomp; no agent-authored development commits, task closes, or new QA bugs in this window. Beads state remains stable with three active in-progress items: red-cell-c2-89o, red-cell-c2-s9d, and red-cell-c2-3h7.

### QA Review — 2026-03-11 22:20 — c1eb030..dedecae

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | Infra only: workspace flatten (crates/ → repo root), removed GitHub Actions CI/release workflows |
| Codex | 2 | 0 | Closed: red-cell-c2-1uoh (duplicate DEMON_INIT rejection — `parse_for_listener` now early-returns `InvalidInit` if agent_id already registered, with test), red-3c6 (client note task operator attribution — code landed in 3c1651e, close commit only). Active: red-5xw in_progress (agent_new_event deduplication + pivot chain fix, unstaged test additions in dispatch.rs and agent_events.rs observed). |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check + clippy -D warnings clean; cargo test: 87 passed)
Notes: Clean sprint. The duplicate DEMON_INIT fix (red-cell-c2-1uoh) is correct — early rejection before any state mutation, plus a deterministic test verifying that stored agent metadata, listener name, and CTR offset are all preserved when a duplicate init arrives. No `unwrap()`/`expect()` in production paths. No violations found. One open P2 bug in_progress (red-5xw) with partial working-tree changes not yet committed.

### QA Review — 2026-03-11 23:35 — dedecae..806efaa

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | QA bookkeeping commit only |
| Codex | 1 | 0 | Closed red-5xw. Added regression coverage in `teamserver/src/agent_events.rs` and `teamserver/src/dispatch.rs`; pivot parent metadata is preserved in shared `AgentNew` events. Claimed red-pkl. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (cargo check clean; cargo clippy --workspace -- -D warnings clean; cargo test: 175 passed, 0 failed; doc-tests clean)
Notes: Reviewed four commits in range; only one agent-authored development change landed, and it is test-only follow-up for the earlier shared `agent_new_event` fix. Current `HEAD` uses the shared builder from both `listeners.rs` and `dispatch.rs`, so closing red-5xw is justified. No new QA bugs filed. Beads state is consistent: one active in-progress issue (`red-pkl`) and no task closures without corresponding implementation.

### Arch Review — 2026-03-12 00:50

| Agent | Findings | Categories | Notes |
|-------|---------:|------------|-------|
| Claude | 0 | — | No new agent-attributed findings this run |
| Codex | 0 | — | Reconfirmed existing open DNS release-build gap (`red-cell-c2-33lj`), but no new Codex-attributed defects were filed |
| Cursor | 0 | — | No new agent-attributed findings this run |

Overall codebase health: drifting
Biggest blindspot: auth and shared-domain review still lacks protocol-hardening around operator identity handling and cross-crate agent-id parsing consistency.
Additional findings filed this run were attributed to Michel Klomp: red-cell-c2-1pb7, red-cell-c2-2znr, and red-cell-c2-2g5q.

### QA Review — 2026-03-12 05:10 — 50e48a4..6872094

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 0 | 0 | No agent-authored development commits in range; reviewed one prior QA bookkeeping commit authored by Michel Klomp |
| Cursor | 0 | 0 | No activity this run |

Build: passed (`cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace`)
Notes: Reviewed one commit from `50e48a4` to `6872094`. The diff only advanced `.beads/qa_checkpoint` and appended a scorecard entry; no Rust, config, or protocol code changed. No new QA bugs were filed. `br list --status=in_progress` and `br ready` returned `database is busy` during this run, while `br list --status=open` succeeded, so beads-state review was partially limited by transient lock contention rather than repository state.

### QA Review — 2026-03-12 05:21 — 6872094..1d882d3

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 0 | 0 | One claim commit in range (`red-cell-c2-3rqy`), but no development or close commits |
| Cursor | 0 | 0 | No activity this run |

Build: passed (`cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace`)
Notes: Reviewed three commits from `6872094` to `1d882d3`. The committed diff only touched `.beads/qa_checkpoint`, `.beads/issues.jsonl`, and `AGENT_SCORECARD.md`; no Rust, TOML, or protocol code changed in the reviewed range, so no new QA bugs were filed. `br list --status=in_progress` and `br ready` succeeded; `br list --status=open` initially returned `database is busy` but succeeded on retry, so beads-state review was completed after transient lock contention cleared.

### QA Review — 2026-03-12 05:50 — 1d882d3..051ed51

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 3 | 0 | Closed `red-cell-c2-3rqy`, `red-cell-c2-1auz`, and `red-cell-c2-89o`. One additional claim commit (`red-cell-c2-1cb1`) remains in progress and is not closed prematurely. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (`cargo check --workspace` and `cargo clippy --workspace -- -D warnings` against committed `HEAD` in `/tmp/red-cell-qa-8ZKUEB`); `cargo test --workspace` is still compiling in that clean worktree as of this review log entry
Notes: Reviewed ten commits from `1d882d3` to `051ed51`, including three Codex feature/fix commits and three Codex task-close commits. No committed build, protocol, security, or architecture regressions were identified in the reviewed Rust/TOML/Markdown diff. Beads state is consistent: `red-cell-c2-1cb1` is the only active in-progress item and remains open, while `br ready` shows it correctly as ready work for follow-up.

### QA Review — 2026-03-12 06:25 — 051ed51..6d30acb

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 0 | 0 | One claim commit in range (`red-cell-c2-q2n1`), but no development or close commits |
| Cursor | 0 | 0 | No activity this run |

Build: passed for `cargo check --workspace` against committed `HEAD` in `/tmp/red-cell-qa-eEtM5J`; `cargo clippy --workspace -- -D warnings` and `cargo test --workspace` were still compiling in that clean worktree at log time due shared target-lock contention
Notes: Reviewed three commits from `051ed51` to `6d30acb`. The committed diff only touched `.beads/qa_checkpoint`, `.beads/issues.jsonl`, and `AGENT_SCORECARD.md`; no Rust, TOML, or protocol code changed in the reviewed range, so no new QA bugs were filed. Beads state is consistent: the only active in-progress items are `red-cell-c2-q2n1` and `red-cell-c2-1cb1`, and neither was closed prematurely. `br list --status=open` succeeded after one transient SQLite lock, while `br list --status=in_progress` and `br ready` completed successfully.

### QA Review — 2026-03-12 06:51 — 6d30acb..af12a8d

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 2 | 1 | Closed `red-cell-c2-34qy` and `red-cell-c2-7369`; one additional claim commit (`red-cell-c2-39z8`) remains in progress. Filed `red-cell-c2-3ilv` for the new hardcoded partial-download inactivity timeout. |
| Cursor | 0 | 0 | No activity this run |

Build: `cargo check --workspace` passed against committed `HEAD` in `/tmp/red-cell-qa-el6bUE`; `cargo clippy --workspace -- -D warnings` is still compiling in isolated target `/tmp/red-cell-qa-el6bUE-target-clippy`, and an earlier `cargo test --workspace` attempt was blocked by shared cargo locks from other local worktrees
Notes: Reviewed nine commits from `6d30acb` to `af12a8d`, including three Codex fix commits, two Codex task-close commits, three Codex claim commits, and one prior QA bookkeeping commit. The committed Rust diff is limited to [teamserver/src/dispatch.rs](/tmp/red-cell-qa-el6bUE/teamserver/src/dispatch.rs) and [teamserver/src/websocket.rs](/tmp/red-cell-qa-el6bUE/teamserver/src/websocket.rs). Listener edit and agent remove audit logging look correct and are covered by new websocket tests. Beads state is consistent: `red-cell-c2-39z8` and `red-cell-c2-1cb1` are the only active in-progress items seen, both still open with matching claim activity, and the two close commits in range have corresponding implementation commits. `br list --status=open` and `br ready` succeeded after transient SQLite lock contention.

### QA Review — 2026-03-12 07:18 — af12a8d..ce83234

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 3 | 0 | Closed `red-cell-c2-39z8`, `red-cell-c2-33lj`, and `red-cell-c2-31w8`; one additional claim commit (`red-cell-c2-4row`) remains in progress. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (`cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace`)
Notes: Reviewed eleven commits from `af12a8d` to `ce83234`, including three Codex fix commits, three Codex task-close commits, two Codex claim commits, one architecture-review bookkeeping commit, one beads-sync commit, and one prior QA bookkeeping commit. The committed Rust diff is limited to [teamserver/src/listeners.rs](/home/michel/Red-Cell-C2/teamserver/src/listeners.rs) and [teamserver/src/main.rs](/home/michel/Red-Cell-C2/teamserver/src/main.rs). No additional QA defects were identified beyond the already-open architecture findings in this range. Beads state is consistent: `red-cell-c2-4row` and `red-cell-c2-1cb1` are the only active in-progress items, both still open with matching claim history, and the three close commits in range have corresponding implementation commits.

### QA Review — 2026-03-12 09:30 — ce83234..df8b7a1

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 2 | 2 | Closed `red-cell-c2-4row` (DNS unbounded tasks) and `red-cell-c2-1cb1` (listener runtime state); filed `red-cell-c2-18ek` (uncommitted okvt work breaks cargo test) and `red-cell-c2-277i` (double DB op on CTR offset init). `red-cell-c2-okvt` newly claimed and in-progress. |
| Cursor | 0 | 0 | No activity this run |

Build: committed HEAD (`df8b7a1`) passes `cargo check --workspace` and `cargo clippy --workspace -- -D warnings`; `cargo test --workspace` cannot be run against committed HEAD because the working tree has uncommitted in-progress changes for `red-cell-c2-okvt` that reference `ShutdownController` (not yet in `lib.rs`), causing compilation failures. See `red-cell-c2-18ek`.
Notes: Reviewed twenty-five commits from `ce83234` to `df8b7a1`. Two substantive implementation commits: `9ed44360` (fix: bound DNS listener packet handling — removes unbounded tokio::spawn per UDP packet, processes inline with backpressure comment and new burst test) and `ae329742` (fix: make agent registration CTR persistence atomic — wraps INSERT+UPDATE in a SQLite transaction, adds two comprehensive rollback tests). Both fixes look correct. The CTR atomicity commit introduces a minor inefficiency: `insert_agent_row` always inserts `ctr_block_offset=0` then issues a separate UPDATE if offset is non-zero, costing two SQL ops in a single transaction instead of one. Filed as `red-cell-c2-277i` (P3 polish). The majority of other commits are Codex claim/close bookkeeping and beads-sync operations.

### QA Review — 2026-03-12 09:55 — df8b7a1..a3473fd

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 2 | 2 | Closed `red-cell-c2-okvt` (graceful shutdown drain) and `red-cell-c2-18ek` (stale shutdown bug); filed `red-cell-c2-lwd1` (SMB/DNS shutdown notifier pinning race) and `red-cell-c2-3phi` (wait_for_callback_drain TOCTOU race). `red-cell-c2-n0em` newly claimed and in progress. |
| Cursor | 0 | 0 | No activity this run |

Build: passed (`cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace`)
Notes: Reviewed five commits from `df8b7a1` to `a3473fd`. One substantive implementation commit: `2ff1c7d` (feat: add graceful teamserver shutdown). Implementation is well-structured — new `shutdown.rs` module with `ShutdownController` (Arc-wrapped atomics + `Notify`), RAII `ActiveCallbackGuard`, propagated into HTTP/SMB/DNS listeners and WebSocket handler. Two P3 bugs filed: (1) `red-cell-c2-lwd1` — SMB and DNS accept loops create a fresh `notified()` future each iteration and can miss a `notify_waiters()` fired between iterations; the websocket handler correctly pins before the loop. (2) `red-cell-c2-3phi` — `wait_for_callback_drain` has a TOCTOU window between the `active_callbacks == 0` check and `.notified()` await, potentially causing a spurious full-timeout delay. Both are low severity and don't affect correctness; the `stop()` call and count re-check after timeout handle them gracefully.

### QA Review — 2026-03-12 10:35 — bec4421..3df9f52

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 3 | 1 | Closed `red-cell-c2-2znr` (username enumeration), `red-cell-c2-1pb7` (hex ID parsing), `red-cell-c2-2nos` (Havoc compatibility test prerequisites); filed `red-cell-c2-2jf8` (test suite slowdown from Argon2 in test setup). |
| Cursor | 0 | 0 | No activity this run |

Build: `cargo check --workspace` and `cargo clippy --workspace -- -D warnings` pass clean. `cargo test --workspace` times out (>120s) with the new Argon2 hashing in test setup — filed as `red-cell-c2-2jf8`. Individual module filters pass: `auth::` (18/18 ok, 23.8s), `api::` (50/50 ok, 7.9s with 4 threads), `agents::` (39/39 ok), `red-cell-common` (91/91 ok).
Notes: Reviewed ten commits from `bec4421` to `3df9f52` (excluding QA checkpoint commit). Three substantive implementation commits by Codex: (1) `b74adf1` — operator login hardening: replaces bare SHA3 password digest storage with Argon2id(SHA3(password)) PHC string verifiers, adds constant-time dummy-user verification path, unifies `AuthenticationFailure` variants to `InvalidCredentials` to prevent username enumeration, adds legacy-upgrade path for existing rows via `normalize_persisted_verifier`, DB migration renames column. Implementation is correct and well-tested (new `from_profile_with_database_upgrades_legacy_runtime_operator_digests` test). One P2 regression: `from_profile` now runs Argon2 synchronously per operator, making every test that constructs `AuthService` expensive — filed as `red-cell-c2-2jf8`. (2) `fd56552` — always parse agent string IDs as hex radix-16; removes ambiguous heuristic that treated digit-only strings as decimal. Three regression tests added. Fix is correct. (3) `fc097e0` — gates Havoc compatibility test behind `havoc_compatibility_skip_reason()` which checks for `RED_CELL_HAVOC_TEAMSERVER_DIR` env var or presence of `src/Havoc/teamserver`, and also checks Go toolchain availability. Uses runtime path substitution in go.mod instead of hardcoded `/home/michel` path. Fix is correct; no new issues.

### QA Review — 2026-03-12 11:00 — 073c2ca..2f10bd8

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this run |
| Codex | 3 | 1 | Closed `red-cell-c2-14fa` (COMMAND_CHECKIN metadata refresh), `red-cell-c2-1t80` (pivot callback dispatch), `red-cell-c2-21yh` (DNS listener gating); filed `red-cell-c2-2lf7` (working_hours silent saturation in parse_checkin_metadata). |
| Cursor | 0 | 0 | No activity this run |

Build: passed (`cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace` — all tests pass this run, Argon2 slowdown from `red-cell-c2-2jf8` did not cause timeout in this run)
Notes: Reviewed eight commits from `073c2ca` to `2f10bd8` (three Codex fix commits, three Codex close/claim bookkeeping commits, two prior QA/test-review bookkeeping commits). The three fixes address real protocol bugs: (1) `983789a` — COMMAND_CHECKIN now parses the full Havoc metadata packet (keys, hostname, process info, OS version, sleep config) and updates the agent registry + resets CTR offset; comprehensive round-trip test added. One new P3 bug filed: `parse_checkin_metadata` inherits the same `i32::try_from(working_hours).unwrap_or(i32::MAX)` silent-saturation pattern already flagged for DEMON_INIT in `red-cell-c2-2x0k`. (2) `f1567c4` — pivot callback dispatch now concatenates all child package responses instead of keeping only the last; covered by new unit test. (3) `a27e7db` — DNS listener `start()` now gates at the API level and sets `Error` status (instead of silently starting and breaking); two new tests validate this. The DNS close commit (`4d19bec`) correctly acknowledges the fix is partial — DNS remains blocked in the payload builder and manager create/update paths. `red-cell-c2-3ath` (restore_running hiding failed restarts) remains open; the DNS-specific restore_running path is now fixed but the general issue persists.

### QA Review — 2026-03-12 13:00 — 2f10bd8..2aa2a07

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | Test-review scan bookkeeping only (scan index advanced to 20) |
| Codex | 3 | 1 | Closed `red-cell-c2-3ilv` (download tracker inactivity), `red-cell-c2-3ath` (restore_running hides failed restarts), `red-cell-c2-15rj` (DNS listener management flows); filed `red-cell-c2-pbmw` (DownloadTracker memory leak on agent death). |
| Cursor | 0 | 0 | No activity this run |

Build: passed (`cargo check`, `cargo clippy -- -D warnings`, `cargo test` — 365+19+17+... tests ok, 32.6s)
Notes: Reviewed eleven commits from `2f10bd8` to `2aa2a07`. Three substantive Codex fix commits: (1) `be34e67` — removes stale-timeout pruning from DownloadTracker; transfers now persist until explicitly closed via finish(). Correct fix for the inactivity bug, but removes the only cleanup path for agent-disconnected transfers — filed `red-cell-c2-pbmw`. (2) `6bfd855` — restore_running() now propagates StartFailed errors except for External listeners; surfaces real bind failures that were previously swallowed. Correct. (3) `1746585` — DNS listeners are now fully unblocked at create/update/start level; External listeners are moved to a profile-validation-time block (rejected before they can be created). Code is clean, tests updated and comprehensive. DNS runtime was already implemented; this just removes the gating layer. No lingering `unwrap()` or `todo!()` introduced.

### QA Review — 2026-03-12 14:00 — 81bfe17..9daef86

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | Arch-review and test-review bookkeeping only |
| Codex | 5 | 0 | Closed `red-cell-c2-2x0k` (working_hours signed saturation), `red-cell-c2-25uh` (operator port fallback identity leak), `red-cell-c2-s7rj` (unknown reconnect probe silent 200), `red-cell-c2-lwd1` (SMB/DNS shutdown race), `red-cell-c2-3phi` (TOCTOU drain race). |
| Cursor | 0 | 0 | No activity this run |

Build: passed (`cargo check`, `cargo clippy -- -D warnings`, `cargo test` — 595 tests ok, ~35s)
Notes: Reviewed sixteen commits from `81bfe17` to `9daef86`. Five substantive Codex fix commits, all clean and well-tested: (1) `77a41cb` — DEMON_INIT working_hours now read as i32 directly via `i32::from_be_bytes(read_fixed::<4>(...))` — correct fix, signed bitmask preserved, regression test with `i32::MIN | 0x2A`. (2) `55194e6` — operator port fallback now returns `StatusCode::NOT_FOUND` with empty body instead of 501 + "not implemented" — security improvement, covered by new router test. (3) `ca00428` — unknown reconnect probes now return fake 404 + create audit entry; `DemonHttpDisposition` enum dispatches HTTP-specific path; SMB/DNS paths also pass `database` for audit logging (but return empty payload / "ack" respectively — acceptable for non-HTTP transports). (4) `fe9f080` — SMB and DNS accept loops now pin shutdown future once before the select loop instead of recreating it each iteration — prevents SIGINT from being missed between iterations; two regression tests. (5) `9daef86` — `ShutdownController::notified()` and `wait_for_callback_drain()` now register the Tokio `Notified` future before checking shared state — eliminates the window where `notify_waiters()` fires between state-check and waiter-registration. No `unwrap()`/`todo!()` in production paths. No new bugs filed.

### Arch Review — 2026-03-12 17:05

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 5 | Security(+1), Protocol(+2), Architecture(+1), Missing tests(+1) | WebSocket no max-message-size; port() returns 0 silently; credential heuristics full-line scan false positives; AgentInfo name collision in common crate; no unit tests for credential extraction |
| Codex | 3 | Security(+1), Protocol(+1), Missing tests(+1) | AES session key replaced from nested checkin payload without freshness check; kill_date u64→i64 silent i64::MAX fallback in 3 locations; no test for CTR key-rotation boundary |
| Cursor | 0 | — | No new Cursor-authored code in scope |

Overall codebase health: on track
Biggest blindspot: AES key rotation via crafted checkin payload in a pivot chain (red-cell-c2-16i3) — the nested-trust assumption is not validated with any freshness mechanism; confirmed clean: timing-safe auth, SQL parameterization, clippy -D warnings enforced, all 658 tests passing.

### QA Review — 2026-03-12 17:10 — 942cc1f..40f278e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity in reviewed commits. |
| Codex | 4 | 0 | Closed red-cell-c2-3b1j, red-cell-c2-1qi3, red-cell-c2-16i3, and red-cell-c2-2xrl; also claimed red-cell-c2-26lc. Reviewed changes in `teamserver/src/dispatch.rs`, `teamserver/src/sockets.rs`, and `teamserver/tests/http_listener_pipeline.rs`; closures match the implemented test/fix scope and no new defects were found. |
| Cursor | 0 | 0 | No activity in reviewed commits. |

Build: passed (`cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace`)

### QA Review — 2026-03-12 17:36 — 40f278e..e95504a

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity in reviewed commits. |
| Codex | 4 | 0 | Closed `red-cell-c2-26lc`, `red-cell-c2-2njj`, `red-cell-c2-2aec`, and `red-cell-c2-vwrf`; one additional claim commit (`red-cell-c2-21jl`) remains in progress and matches `br list --status=in_progress`. The Rust diff is limited to `common/src/config.rs`, `teamserver/src/demon.rs`, `teamserver/src/dispatch.rs`, and `teamserver/tests/database.rs`; fixes are correctly scoped and fully covered by new regression tests. |
| Cursor | 0 | 0 | No activity in reviewed commits. |

Build: passed (`cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace`)

### QA Review — 2026-03-13 — e95504a..49c03b4

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity in reviewed commits. |
| Codex | 1 | 0 | Closed `red-cell-c2-21jl`; added 3 unit tests to `common/src/error.rs` covering display messages, field preservation, and clone/equality. Tests are correct and well-scoped. No defects found. |
| Cursor | 0 | 0 | No activity in reviewed commits. |

Build: passed (`cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace` — 107 tests, 0 failed)

### QA Review — 2026-03-14 14:25 — 446ae04..08aff95

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 1 | Arch-review, test-review scan (31 new test-quality tasks filed), ID normalization. Filed `red-cell-c2-klso` (P2): fix for `red-cell-c2-3qq0` implemented but left uncommitted in git stash — workflow violation by Ubuntu-C2-dev02-claude. |
| Codex | 0 | 0 | No activity this run. |
| Cursor | 0 | 0 | No activity this run. |

Build: passed (`cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓; `cargo test` skipped — no Rust source changes in committed range)
Notes: Reviewed 10 commits from `446ae04` to `08aff95`. No Rust source changes in committed state. Activity was exclusively review/bookkeeping: arch-review loop filed 6 issues; test-review loop filed 31 test-quality tasks scanning the entire teamserver test suite; two ID-normalization commits fixed mismatched `red-` prefixes in issues.jsonl; one claim commit for `red-cell-c2-3qq0` (Ubuntu-C2-dev02-claude). The actual fix for `red-cell-c2-3qq0` (all-zero AES IV rejection in `parse_init_agent` + regression test) is present but stranded in `git stash` — filed `red-cell-c2-klso` as P2 workflow bug and blocked `red-cell-c2-3qq0` on it. Two P1 security issues remain open: `red-cell-c2-3qq0` (DEMON_INIT IV check, fix ready in stash) and `red-cell-c2-bfih` (CHECKIN IV check, not started). Recommend prioritizing both before any new features.

### QA Review — 2026-03-15 — 08aff95..896603b

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 47 | 0 | Very productive sprint: 47 issues closed across protocol fixes, security hardening, test coverage, and refactors. Key deliverables: fix(tls) cert persistence across restarts, fix(agents) persist-before-mutate for CTR offset/encryption, fix(auth) constant-time session token scan, fix(protocol) truncated CHECKIN rejection, fix(crypto) AES key/IV zeroize (bhvi), fix(agents) cycle detection arg order (cool), fix(teamserver) job queue depth cap (33iq), fix(listeners) unknown agent audit entry + DNS registry gate. Extensive test additions across sockets, auth, webhook, audit, protocol, DB cascade. No new bugs found in code review. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (125+ tests, 0 failed)
Notes: Reviewed 113 commits from `08aff95` to `896603b`. All productive commits attributed to Ubuntu-C2-dev01-claude (Claude Sonnet 4.6). One notable admin commit `896603b` (by user+Claude) adjusts loop intervals (QA→30min, arch→105-135min) and adds service-bridge validation with tests. P2 security issues still open and now claimed: `red-cell-c2-2n8o` (timing oracle), `red-cell-c2-3hro` (unbounded queue), `red-cell-c2-a74c` (CHECKIN key rotation). `red-cell-c2-35jc` (external listener) remains in_progress. Codebase health trending strongly positive.

### QA Review — 2026-03-15 — 795c7ad..3663234

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 0 | Closed red-cell-c2-35jc (External listener removed from shared types — clean arch fix), red-cell-c2-12rd (8 listener lifecycle event payload tests), red-cell-c2-1b3x (3 ListenerManager constructor/shutdown/cleanup-hook tests). All work high quality: no unwrap, no missing coverage, correct behavior. One stashed sockets.rs test (vm2a) is in-progress. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test -p red-cell --lib` ✓ (533 tests, 0 failed)
Notes: Reviewed 10 commits from `795c7ad` to `3663234`. All productive work attributed to Ubuntu-C2-dev01-claude (Claude Sonnet 4.6). Key highlight: `fix(protocol): remove External listener from shared domain types` cleanly excises the never-implemented External transport from all code paths (domain, listeners, payload builder, API schema, tests). Profile validation retains an explicit rejection with user-facing error. `sync_profile` now silently skips External entries — acceptable since profile.validate() gates this in production. No new bugs filed. Codebase health: strong.

### QA Review — 2026-03-15 14:30 — 897414b..19b96f8

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No new dev commits in range. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (3 tests, 0 failed)
Notes: Only commit in range was the previous QA checkpoint itself. 14 issues remain stuck `in_progress` (wf2d, mut8, s3a9, 1x9h, 2u74, 3bdz, 2qfs, 3inc, 11aj, 2tru, 35k0, 3uhe, 2z11, 2h4n) — agent claiming but not completing. Workflow bug `red-cell-c2-olwt` remains open. No scorecard changes this run.

### Arch Review — 2026-03-15 (fresh-eyes run)

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 1 | Security | red-cell-c2-da0m: no cap on simultaneous operator sessions degrades constant-time session token scan (P3) |
| Codex | 0 | — | No new findings attributed |
| Cursor | 0 | — | No new findings attributed |

Overall codebase health: on track
Biggest blindspot: CTR offset continuity after restart remains unverified (red-cell-c2-h5a3, red-cell-c2-3qbl still open). A keystream collision after crash-restart would expose all traffic for the affected agent session without any server-side warning.
Notes: Full build and 607+ test suite passes clean. All previously filed security and protocol issues remain correctly tracked. The codebase has matured significantly — zero unwraps/expects/todos in production code, all user-supplied length fields bounded before allocation, key material redacted from all log output. The session-inflation finding (da0m) is the only net-new issue this run.

### QA Review — 2026-03-15 15:00 — 19b96f8..5bc1577

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | Only QA/arch-review commits in range — no dev work. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (884 tests across all crates, 0 failures)
Notes: No dev commits in range — only two QA checkpoint/arch-review commits by Claude. 14 test-coverage issues remain in_progress (wf2d, mut8, s3a9, 1x9h, 2u74, 3bdz, 2qfs, 3inc, 11aj, 2tru, 35k0, 3uhe, 2z11, 2h4n). No new bugs filed this run. Codebase remains clean.

### QA Review — 2026-03-15 15:15 — bf019ad..935d689

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 10 | 0 | Closed `red-cell-c2-2u74` (parse_working_hours missing-separator tests), `red-cell-c2-3bdz` (parse_working_hours end-before-start and equal-time tests), `red-cell-c2-2qfs` (EventReceiver::recv channel-closed path), `red-cell-c2-3inc` (COMMAND_CHECKIN truncated inner payload protocol test), `red-cell-c2-11aj` (audit: populate DB before querying unknown session activity), `red-cell-c2-2tru` (bool_from_i64 rejects negative values), `red-cell-c2-35k0` (mark_stale_agent_if_unchanged skips already-dead agent), `red-cell-c2-3uhe` (AuditRecord::try_from returns InvalidPersistedValue when id is None), `red-cell-c2-2z11` (SessionRegistry replaces old session on same connection_id), `red-cell-c2-2h4n` (authenticate_message rejects invalid JSON). All test-only additions. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (909 tests, 0 failures)
Notes: Excellent run — Claude closed 10 test-coverage issues in one pass, clearing most of the backlog that was stuck in_progress since last review. Code quality is high: all tests well-structured, proper error variant matching, no unwraps in production paths, DB seeded correctly in query tests. `red-cell-c2-1x9h` (checkin_windows arch/version label tests) remains in_progress and still open. No new bugs filed.

### QA Review — 2026-03-15 15:30 — 935d689..9c20ead

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 9 | 0 | Closed `red-cell-c2-1x9h` (checkin_windows arch/version label tests), `red-cell-c2-s3a9` (load_plugins Python syntax error path), `red-cell-c2-mut8` (extractor tests for ListenerManagementAccess and TaskAgentAccess), `red-cell-c2-wf2d` (negotiate_socks5 rejection path tests), `red-cell-c2-h9be` (read_socks_connect_request unsupported command/unknown atyp tests), `red-cell-c2-3c6g` (encode_fs_payload coverage for 8 filesystem sub-commands), `red-cell-c2-hn9t` (filesystem_subcommand rejects unknown), `red-cell-c2-mnw3` (execute_registered_command returns false for unknown command), `red-cell-c2-lpg5` (notify_audit_record_detached drop-when-closing test). All pure test additions — no production code changed. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (914 tests, 0 failures)
Notes: Clean run. All 9 closes are valid: 6 paired with direct implementation commits this cycle, 3 (wf2d, h9be, lpg5) correctly recognized pre-existing tests and closed with accurate descriptions. No unwraps in test or production code. One issue currently in_progress: `red-cell-c2-ude5` (security: all-zero IV accepted during DemonInit without rejection) — this is the next task claimed at HEAD. No bugs filed.

### Arch Review — 2026-03-15 (deep independent review)

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Codex | 1 | Security/OPSEC | red-cell-c2-k00o (P2): fake_404_response() unconditionally sets `x-havoc: true` response header in teamserver/src/listeners.rs:927, fingerprinting the C2 server to any network scanner |
| Claude | 0 | — | No new findings attributed |
| Cursor | 0 | — | No new findings attributed |

Overall codebase health: good — zero production unwraps/expects/todos, all user-supplied lengths bounded before allocation, key material absent from logs, constant-time comparisons in auth paths, rate limiting on both DEMON_INIT and operator logins.
Biggest blindspot: CTR offset continuity after crash-restart remains unverified (red-cell-c2-h5a3, red-cell-c2-3qbl still open). Keystream collision after restart would silently expose all traffic for the affected agent with no server-side warning.
Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (914 tests, 0 failures)
Notes: Full codebase audit (security, protocol correctness, error handling, architectural drift, test coverage, consistency, completeness). One net-new issue filed: `red-cell-c2-k00o` — x-havoc OPSEC header leak introduced by Codex in commit 8460d624. All other previously identified risks (da0m, h5a3, 3qbl) remain correctly tracked and unchanged.

### QA Review — 2026-03-15 — 904ead4..bdf61d3

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 6 | 0 | Closed `red-cell-c2-n950` (replace all-zero DUMMY_PASSWORD_HASH with random Argon2 PHC verifier + OnceLock test cache), `red-cell-c2-35d7` (three TLS config tests: auto-generate+persist, reload stable on restart, use configured cert paths), `red-cell-c2-mvcp` (validate_define() sanitizes all compiler -D defines against injection), `red-cell-c2-ipj0` (gate havoc_compatibility behind `havoc-compat` feature; panic on missing Go instead of silent Ok(())), `red-cell-c2-235t` (MIN_ENVELOPE_SIZE guard + 4 short-buffer unit tests in DemonEnvelope::from_bytes), `red-cell-c2-5yg3` (all-zero IV DemonInit test, recognized pre-existing fix in commit 6770ac9). Production changes: auth.rs, payload_builder.rs, common/src/demon.rs, teamserver/tests/havoc_compatibility.rs, teamserver/Cargo.toml. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (931 tests, 0 failures)
Notes: Excellent quality cycle. All 5 substantive fixes are correct, well-scoped, and accompanied by targeted tests. validate_define() properly validates only the NAME portion of compiler defines (not the value), avoiding false rejections of CONFIG_BYTES hex values. generate_dummy_verifier() correctly uses Uuid::new_v4() as entropy input for Argon2 hashing, with OnceLock cache for test performance. The havoc-compat feature gate is the right approach — silent Ok(()) was masking missing Go toolchain. No unwrap()/expect() in new production paths. No hardcoded secrets. AES key material not logged. No bugs filed.

### QA Review — 2026-03-15 13:30 — c98ea0f..26f1378

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed `red-cell-c2-5q73` (populate `process_path` from full binary path in `AgentRecord`, fixes `demon.rs`/`dispatch.rs`/`database.rs` + migration), `red-cell-c2-lqzt` (surface `os_build` in `AgentRecord` and `OperatorAgentInfo`, fixes `agent_events.rs`/`database.rs`/`api.rs` + migration). Also 14 claim commits for new issues. **Warning**: uncommitted implementation of `red-cell-c2-xfkr` (pivot list callback) present in local working tree stash — must be committed before session end to avoid loss. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (937 tests, 0 failures)
Notes: Both fixes are correct and complete. DB migrations use `NOT NULL DEFAULT` for safe column addition. New fields properly thread through domain → DB → protocol → API layers. Three targeted tests added in `agent_events.rs` covering `os_build` population, zero-value case, and `process_path` ≠ `process_name` invariant. No unwrap()/expect() in production paths. No hardcoded secrets. No bugs filed. Main concern: stashed-but-uncommitted `dispatch.rs` changes implementing `red-cell-c2-xfkr` (pivot list callback with two integration tests) — code quality is good but it will be lost if the stash is dropped.

### QA Review — 2026-03-15 16:00 — 24869d7..8ac42f5

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 5 | 2 | Closed `red-cell-c2-xfkr` (pivot list callback), `red-cell-c2-2me2` (webhook shutdown race), `red-cell-c2-q9re` (auth rate limiter), `red-cell-c2-zroy` (TLS key zeroization), `red-cell-c2-j8a0` (getrandom HMAC secret). Filed `red-cell-c2-0bm2` (P3): pivot list uses `{:<08x}` — left-aligned zero-padding puts zeros on the right for short demon IDs; should be `{:08x}`. Filed `red-cell-c2-psa8` (P3): auth failure rate limiter in api.rs re-implements `FailedApiAuthWindow`/prune/evict helpers instead of reusing the generic `rate_limiter.rs` module, adding a third eviction-pattern copy. Also: HEAD commit 8ac42f5 claims already-closed issue `red-cell-c2-5rtk` — ongoing instance of red-cell-c2-olwt. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (659 tests, 0 failures)
Notes: All five fixes are substantively correct and include tests. The shutdown race fix (webhook.rs) is particularly well done — the increment-before-check pattern correctly closes the race window and the new test exercises the concurrent code path with a real HTTP server. The auth rate limiter is functionally sound but reintroduces eviction code that already lives in rate_limiter.rs. The pivot list formatting bug is subtle and only manifests for demon IDs with fewer than 8 hex digits. No unwrap()/expect() in production paths. No hardcoded secrets.

### QA Review — 2026-03-15 17:00 — 66f78ef..36efd87

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 4 | 1 | Closed `red-cell-c2-0ff3` (HTTP method validation), `red-cell-c2-b44y` (is_weak_aes_key/iv extraction), `red-cell-c2-yh94` (MAX_AGENT_MESSAGE_LEN consolidation), `red-cell-c2-2hd9` (rate_limiter.rs extraction). Also added token-limit backoff + post-run WIP cleanup to dev loop. Filed `red-cell-c2-t4ml` (P2): `add_wstring(out, method)` in payload_builder.rs:643 writes method verbatim — case-insensitive validation lets "post" through but the binary embeds "post" not "POST", breaking HTTP callbacks (RFC 7230 §3.1.1). Note: `red-cell-c2-psa8` (`api.rs` rate-limiter duplication) remains open — the `rate_limiter.rs` extraction resolved `listeners.rs`/`websocket.rs` but left `api.rs` unmigrated. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (967 tests, 0 failures)
Notes: Four refactoring tasks are clean and well-executed. `rate_limiter.rs` is a textbook extraction — generic over `K`, with three dedicated tests. `is_weak_aes_key`/`is_weak_aes_iv` helpers are well-documented including the vacuously-true empty-slice edge case. The HTTP method allowlist is a genuine correctness improvement over the previous GET-only reject. One protocol regression introduced: method case not normalized before binary serialization. `api.rs` rate-limiter duplication is the sole outstanding carry-over from last review cycle.
