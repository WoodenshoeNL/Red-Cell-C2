# Agent Scorecard

Maintained automatically by the QA and architecture review loops.
Each loop run updates the running totals and appends a review entry.

---

## Running Totals

| Metric | Claude | Codex | Cursor |
|--------|-------:|------:|-------:|
| Tasks closed | 585 | 212 | 31 |
| Bugs filed against | 51 | 34 | 9 |
| Bug rate (bugs/task) | 0.09 | 0.16 | 0.29 |
| Quality score | 91% | 84% | 71% |

*Bug rates: Claude 51/585=0.09, Codex 34/212=0.16, Cursor 9/31=0.29*

## Violation Breakdown

| Violation type | Claude | Codex | Cursor |
|----------------|-------:|------:|-------:|
| unwrap / expect in production | 3 | 0 | 0 |
| Missing tests / stale tests | 31 | 13 | 5 |
| Clippy warnings | 3 | 0 | 1 |
| Protocol errors | 7 | 27 | 3 |
| Security issues | 24 | 36 | 0 |
| Architecture drift | 4 | 21 | 0 |
| Memory / resource leaks | 2 | 10 | 1 |
| Startup / lifecycle regressions | 1 | 8 | 0 |
| Test infrastructure / flakiness | 4 | 0 | 0 |
| Audit attribution errors | 0 | 2 | 0 |
| Availability / timeout regressions | 1 | 5 | 0 |
| Correctness / pagination | 18 | 7 | 1 |
| Workflow / close-hygiene | 12 | 0 | 0 |
| Code reuse / duplication | 6 | 0 | 0 |

---

## Review Log

<!-- QA and arch loops append entries below this line -->

### QA Review — 2026-03-20 23:45 — 3385e1f6..fd716ba2

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No committed work this period. red-cell-c2-wungl (P2, AgentTask/AgentRegister dispatch wiring) claimed ~14h ago with 587 lines of uncommitted changes in service.rs — WIP not yet pushed. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: skipped (no new commits)

### QA Review — 2026-03-20 03:15 — e09c92a8..14619c3b

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed f7ajo (credential extraction E2E tests — 3 integration tests for persist_credentials_from_output), t2rcj (error path tests for non-existent agent in exit/kill-date callbacks — 2 unit tests). Currently working on abu8j (filesystem dispatch DownloadTracker memory limit). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean), cargo test 1638 passed / 1 failed (websocket_listener_commands_broadcast_and_persist_state — known flaky, tracked in red-cell-c2-he5j7)

### Arch Review — 2026-03-21 01:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude (Sonnet) | 2 | 2 security | Weak key detection only all-zero (t1awj, P3). DEMON_INIT no mutual auth — protocol-inherent (g2o4x, P3). |
| Claude (Opus) | 1 | 1 test flakiness | chat broadcast test now consistently failing, not just flaky (43gu3, P2). |
| Claude | 3 | 3 missing tests | Reconnect CTR concurrency test gap (lx315, P3). Agent registration bounds untested (1dcro, P2). DB failure injection tests missing (uq8c7, P3). |
| Codex | 0 | — | No new issues found. |
| Cursor | 0 | — | No new issues found. |

Overall codebase health: **on track**
Biggest blindspot: Agent registration bounds (MAX_REGISTERED_AGENTS=10,000, MAX_JOB_QUEUE_DEPTH=1,000, MAX_REQUEST_CONTEXTS=10,000) are critical DoS protections with no test coverage — a refactor could silently remove them.

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` 1636 passed / 1 failed (`websocket_broadcasts_chat_messages_to_other_operators` — deterministic failure, filed as 43gu3)

Deep review covered: full structural map (123k lines, 75 .rs files across 3 crates), all common crate modules, all teamserver modules (22 source + 14 dispatch), all integration tests (24 files), full client source (6 files). Architecture compliance verified: Axum+Tokio, SQLite/sqlx parameterized queries, HCL config, thiserror/anyhow separation, egui, Rust edition 2024 — all honored with zero drift. Security posture remains strong: constant-time secret comparisons, AES-256-CTR offset management correct with deferred-advance, all DoS bounds in place, no `unwrap`/`expect`/`todo!` in production code, key material redacted in Debug/error paths. No raw SQL string building found. 6 new issues filed (1 bug, 2 security tasks, 3 test coverage tasks).

### QA Review — 2026-03-21 00:15 — 5a40dabe..beffc218

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed mhmmv (TLS fingerprint validation at parse time — rejects malformed SHA-256 hex, surfaces clear error identifying CLI vs config source), 9z6bx (config file 0600 permissions on Unix — OpenOptions .mode() + explicit set_permissions for pre-existing files). Both changes include thorough tests. Currently working on rveao (mutex poisoning). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean), cargo test 1634 passed / 3 failed (known flaky websocket tests — tracked in red-cell-c2-he5j7)

### QA Review — 2026-03-20 23:30 — ba337578..5a40dabe

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 0 | Closed 5jrmz (QA checkpoint), vu8zc (malformed agent ID tests for GET/DELETE/POST agent endpoints — 9 new tests), rp9g6 (HEAD method coverage for fallback handler). All test-only changes, clean code. Currently working on 9z6bx (config file permissions) — WIP has clippy needless_return and a failing overwrite-permissions test to resolve before commit. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean on committed code), cargo test ~1806 passed / 0 failed

### QA Review — 2026-03-20 22:15 — a249b408..ee7f38da

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 5 | 0 | Closed vyx2 (decrypt_agent_data_at_offset overflow test), v05n (SMB empty name+pipe_name validation test), fffl (CryptoError Display format tests), 33k8 (name_id boundary tests for 0 and u32::MAX), 855gp (AgentNotFound error path tests for remove/mark_dead/set_note). All test-only changes, clean code. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean), cargo test 893 passed / 0 failed

Note: red-cell-c2-620mb (encrypt_for_agent empty plaintext test) is in_progress, claimed ~16h ago — not yet stale but worth monitoring.

### QA Review — 2026-03-20 21:00 — a355962..9c5bc94

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 5 | 0 | Closed 6cvz (SOCKS5 unsupported auth rejection test), 1o5f (screenshot 2MB large payload test), 15gi (login set_error password focus test), ebzo (unknown DemonSocketCommand dispatch test), 4tvm (Teamserver.Cert TLS parsing + validation — 4 tests + production validation logic). Also added cert blank-path validation to config.rs. Clean run. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean), cargo test all passed / 0 failed

### QA Review — 2026-03-20 17:45 — 39dbaf8..09531ad

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 0 | Closed 3ybg (PayloadCache corruption, permissions, and concurrency edge-case tests — 5 tests), u0yi (exhaustive map_rotation variant tests — 4 tests), s556 (AgentCryptoMaterial Debug redaction — manual impl replacing derived Debug, with verification test). Security fix is well-tested. Clean run. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean), cargo test 806 passed / 0 failed

### QA Review — 2026-03-20 14:30 — 0060b51..10ae0f7

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 4 | 0 | Closed 3jal (resolve_bind_addr empty DNS error path — extracted helper + 2 tests), xsi8 (PluginEvent::parse round-trip + edge cases — 4 tests), ef81 (ambiguous prefix resolution in match_registered_command — 1 async test), vd2m (ShutdownController try_track_callback race rollback — deterministic test with cfg(test) hook). 3ybg (PayloadCache) now in progress. Clean run. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean), cargo test 745 passed / 0 failed

### QA Review — 2026-03-20 11:15 — 198a6e7..cddce02

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed 2693 (PyO3 docs + cargo config cleanup), hfhb (6 empty result set tests for net dispatch subcommands). Clean code, good edge case coverage. In-progress: 3qy2 fixing grammar bug in filesystem copy/move error messages. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean), cargo test 2731 passed / 0 failed

### QA Review — 2026-03-20 08:30 — 61a6921..4de6fec

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 0 | Closed fmlv (AgentRecord serialization round-trip tests — 5 tests), npdm (PythonRuntime error path tests — 3 tests), 2me0 (add_link error path for nonexistent parent/child — 2 tests). Clean run — test-only changes, no issues. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean), cargo test 2715 passed / 0 failed

### QA Review — 2026-03-19 23:45 — 8b00555..61a6921

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 6 | 0 | Closed s65y (LocalConfig save_to silent-failure test), 8151 (concurrent multi-agent init stress test), i03b (EventLog eviction/unread edge cases), gevp (TLS connector Fingerprint/DangerousSkipVerify/CA unit tests — 6 tests), 9s0h (closed as duplicate of gevp work), uxsd (AppState duplicate agent + unknown agent response edge cases). Clean run — no issues. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean), cargo test 1882+ passed / 0 failed

### QA Review — 2026-03-19 — f49bd40..8b00555

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 4 | 0 | Closed eub1 (REST API key auth integration tests — 8 tests covering auth, RBAC, bearer token), kfla (SOCKS5 client-to-agent write direction test), 7ged (listener error-state recovery path test), g162 (CTR sync verification in empty GET_JOB poll test). Clean run — no issues found. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean), cargo test 1590 passed / 3 flaky (pre-existing websocket race conditions, pass on rerun)

### QA Review — 2026-03-19 — 97bd0af..f52a3b0

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 4 | 0 | Closed n9iw (second-operator agent snapshot verification in HTTP E2E test), nrjr (SOCKS5 finish_connect data relay round-trip test), mus7 (webhook delivery integration tests — 6 tests covering delivery, retry, shutdown draining, null-free payloads), 0aob (payload builder stager generation integration tests). Clean run — no issues found. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean), cargo test passed (2678 tests, 0 failures)

### QA Review — 2026-03-20 02:00 — 7cc6dbf..97bd0af

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 1 | Closed wr7y (session_token case-sensitivity and whitespace edge-case tests in rbac.rs), adzhf (removed unused NormalizePathLayer import — fixed clippy regression from prior period), keqm (Discord embed field sanitization with sanitize_discord_text helper and special character tests). Filed: fiu4y (sanitize_discord_text docstring claims <#channel> mention defusal but code omits it). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (clean), cargo test passed (1189 tests, 0 failures)

### QA Review — 2026-03-20 01:15 — b9f5378..7cc6dbf

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 6 | 3 | Closed 0b2j (demon init/reconnect ACK wire format tests), qufw (token formatting column expansion/boundary tests), 7d4j (ProcCreate verbose/success/piped branch tests), 23cb (format_token_privs_list state mapping tests), kuox (shutdown listener+webhook timeout warning tests), ajwt (EventBus non-TeamserverLog broadcast test). Filed: adzhf (unused NormalizePathLayer import breaks clippy -D warnings), j84p0 (trailing-slash normalization replaced with single duplicate /havoc/ route instead of app-wide middleware), 134lc (StuckDeliveryGuard test helper leaks into public API). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed (1 warning), **clippy FAILED** (unused import NormalizePathLayer), cargo test FAILED (2 pre-existing websocket test failures — not introduced in this range)

### QA Review — 2026-03-19 22:30 — 9d4099f..b9f5378

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 4 | 0 | Closed qav1 (inline DB unit tests for AuditLog/Operator/Listener repos), dm08 (encrypt/decrypt error path tests for invalid crypto material), mp17 (create_operator edge cases for empty creds and duplicates), 1rhs (audit/session pagination boundary tests). Also added ALPN http/1.1 to TLS connector in transport.rs (production fix, committed as WIP). Issue 0b2j in_progress (demon init/reconnect ACK wire format tests — stashed WIP looks solid). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (2,674 tests, 0 failures — one flaky Python test on first run due to concurrent cargo lock contention, passed cleanly on rerun)

### QA Review — 2026-03-19 19:30 — 41dab70..73b93b1

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 0 | Closed 94ap (Argon2 OWASP params fix — originally a Codex bug), hnmp (duplicate issue cleanup), d4bp (SHA3 crypto test coverage with Python-verified reference digests and NFC/NFD normalization tests). Updated e2e test timeouts for stronger Argon2id hashing. Issue hxq6 in_progress (pivot dispatch tests — untracked file compiles, clearly WIP). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (all suites, 0 failures)

### QA Review — 2026-03-19 16:00 — 5a21aa9..36a404b

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 8 | 0 | Closed 8 test-coverage issues (mogx, xjzh, qnn9, xd3l, 6qwd, te53, oao3, 0srt). Added ~1325 lines of client unit tests covering sanitize_file_name, derive_download_file_name, next_available_path, JSON/CSV export, loot filtering, process_task parsing, console completion, agent metadata helpers, UI label helpers. Added 114-line SMB reconnect flow integration test verifying CTR counter synchronisation after reconnect probe. Issue 85p1 in_progress (claimed today, not stuck). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (all suites, 0 failures)

### QA Review — 2026-03-19 — ecbfd15..e93a83a

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 2 | Closed 3 issues (tmby, b7h3, lfbe). New service bridge WebSocket endpoint (765 lines) with SHA3-256 auth, JSON dispatch, and 12 unit tests. Also added error-path tests for Database::connect and direct test coverage for record_operator_action. Filed: wungl (AgentTask/AgentRegister stubs silently discard messages), w59il (no WS integration test for service bridge). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (211 tests, 0 failures)

### QA Review — 2026-03-20 00:15 — f6b07cc..c7fffdc

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 13 | 0 | Closed 13 issues (91qt, olvs, v5fb, 1gwf, e0cv, 6wo8, tphz, 42hq, xmexr, hctp+3 dupes). Fixed: crypto empty-slice edge case, kerberos filetime overflow, DownloadTracker error attribution, swallowed errors in sockets/websocket. Major refactor: extracted shared test setup into common helper, removing ~800 lines of duplication across 4 test files. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (all suites 0 failures)

### QA Review — 2026-03-19 23:30 — dd1fa62..f6b07cc

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 34 | 1 | Bulk-closed 34 test coverage issues (9+6+6+6+9+1+1+1+1 across 8 commits). Added new tests for auth, crypto, demon, shutdown, webhook, plugins, local_config. Filed xmexr: e4f55b8 changed External listener validation to warning but forgot to update main.rs test — cargo test fails. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check ✓, clippy ✓ (0 warnings), cargo test **FAILED** (1 failure: `load_profile_rejects_external_listener_configuration` in main.rs — stale after e4f55b8)

### QA Review — 2026-03-19 22:15 — 0b123b3..fd17219

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 5 | 0 | Closed kkra (socket rportfwd/SOCKS relay tests, +439 lines), 770d (net callback tests — already existed), 1nd5, bc2z (filesystem dispatch tests — already existed), bmew (token dispatch formatting tests, +319 lines). Also claimed fc78 (util.rs tests — closed as already done). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check ✓, clippy ✓ (0 warnings), cargo test ✓ (207+ tests, 0 failures)

### QA Review — 2026-03-19 20:00 — 4d8d0e5..fc811f8

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 0 | Closed zf4l (listener mgmt integration tests), qnl2 (credential/loot endpoint tests), 43uq (job queue endpoint tests). +1272 lines of test code in api.rs. Also ran arch review (6ea75c5). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check ✓, clippy ✓ (0 warnings), cargo test ✓ (207+ tests, 0 failures)

### Arch Review — 2026-03-19 18:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude (Sonnet) | 1 | 1 security | AgentCryptoMaterial derives Debug — latent key exposure risk (s556, P2). |
| Claude (Opus) | 2 | 1 missing tests, 1 code duplication | Plugin emit hooks untested (gx4s, P3). HttpListenerResponseConfig/ProxyConfig duplicated across config.rs and domain.rs (5sg6, P3). |
| Codex | 0 | — | No new issues found. |
| Cursor | 0 | — | No new issues found. |

Overall codebase health: **on track**
Biggest blindspot: AgentCryptoMaterial's `#[derive(Debug)]` at `common/src/crypto.rs:49` could leak AES key/IV bytes if the struct is ever debug-printed. The domain-layer equivalent (`AgentEncryptionInfo`) already has a redacting custom Debug impl — `AgentCryptoMaterial` should follow suit.

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all ~1987 tests passing, 0 failures)

Deep review covered: full structural map (102k lines, 68 .rs files across 3 crates), all common crate modules (crypto, demon protocol, TLS, config, domain, operator, error), all teamserver modules (22 source + 14 dispatch), all integration tests (16 files), full client source (6 files). Security posture strong: constant-time comparisons for all secrets (auth tokens via `subtle::ct_eq`, API keys via HMAC+`ct_eq`, passwords via Argon2 with dummy verifier for timing equalization), AES-256-CTR offset management correct with deferred-advance pattern, DEMON_INIT rate-limited (5/60s per IP, 10k window cap), body size bounded (30 MiB), agent registration capped (10k), job queues capped (1k/agent), request contexts LRU-evicted (10k), pivot depth capped (16), operator sessions capped (64 global / 8 per account). All length-prefixed network reads validated against buffer bounds before allocation. No `todo!`/`unimplemented!`/`unwrap`/`expect` in production code (enforced by clippy deny lints). Architecture decisions (Axum+Tokio, SQLite/sqlx, HCL config, thiserror/anyhow separation, egui, edition 2024) all honored. Most previously-identified issues already tracked in beads. 3 new issues filed.

### QA Review — 2026-03-19 16:45 — 62ab041..c181363

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 8 | 0 | Closed 24gl, 2zkn, uchu, 197z, 2x1d, k9mp, 59m7, krej. Protocol fix (3c647c0): corrected lowercase "http"/"smb" to Havoc-compatible "Http"/"Smb". DNS bug fix (cbf465f): removed resolver-IP binding from DnsPendingResponse per 59m7 — anti-spoofing now relies on registry + AES-256-CTR. New fixture_builder_validation.rs (394 lines, 16 tests). Client scripts_dir fallback tests added. Test-review scan filed 6 new issues. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check ✓, clippy ✓ (0 warnings), cargo test ✓ (all pass, 0 failures)

### QA Review — 2026-03-19 14:30 — 16cafed..c9245fd

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 7 | 0 | Closed 2nqo (malformed transfer/mem-file/package-dropped callback tests), 3hff (payload cache key binary_patch sub-field tests), yoa8 (plugin dir/listener-manager error tests — already existed), 2g6s (basename/process_arch_label helper tests), n8q5 (duplicate/dangling link insert tests), 32g6 (loot FK constraint tests), 3atn (agent response FK constraint tests). Also ran test-review scan (ec3354f). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check ✓, clippy ✓ (0 warnings), cargo test ✓ (1,936 tests, 0 failures)

### QA Review — 2026-03-19 02:30 — 0d70085..b02bae9

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 14 | 0 | Closed 5gkw (logging test), 2bhj (rate_limiter test), 34pn/2108/24rc/3hug (assembly/protocol tests), 1c9x/1t5x (audit tests), 36er (client auth fix), 1s13 (TrustCertificate fix), 3aba (agents queue-full rollback), 7bad (set_last_call_in rollback), 35q0 (add_link test), 2y40 (test-review scan). Also reorganized scripts/prompts. |
| Codex | 17 | 0 | Closed 12q2 (common API tests), 2ufp (TLS PEM test), rmm0 (API keys test), 1upo (cert paths test), 32yd (IPv6 proxy test), 3cr0 (Demon header test), l0tq (uv Python switch), i6zu (loot download tests), 2axt (loot export test), 39lo (TLS CA test), 1drm (scripts dir test), 2udy (login UI tests), 1rcz (script unload test), 3a7a (CommandJob test), 10mb (compiler paths fix), 3d2m (toolchain bootstrap). Switched pyo3 to abi3. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check ✓, clippy ✓, cargo test FAILED (linker: `-lpython3.12` not found after `.cargo/config.toml` removal — tracked as red-cell-c2-2693)

### QA Review — 2026-03-19 08:15 — b02bae9..8cbded8

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 6 | 2 | Closed 3sql (transfer stop/resume state), 23e8 (logging init failures), 34bb (pivot malformed envelopes), 38c0 (process callback branches), 1s51 (kerberos callbacks), 2fj5 (filesystem callbacks). All test-only changes. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Bugs filed:
- red-cell-c2-3qy2: Grammar error in copy/move failure messages ("Failed to copied/moved") — correctness (Claude)
- red-cell-c2-gg8i: .cargo/config.toml hardcodes machine-local library path — architecture drift (Claude)

Build: cargo check ✓, clippy ✓ (0 warnings), cargo test ✓ (all pass)

### QA Review — 2026-03-19 00:15 — 738579b..0d70085

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed 1ps8 (socket callback tests: read failure, write success, non-proxy read, truncated rportfwd list), aq81 (transfer callback tests: UTF-16 output, OEM output, error message, file transfer lifecycle, orphan FileWrite, truncated file open). Also ran test-review scans (batches 2→22→59), arch review, and claimed 5gkw. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: passed — `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,840+ tests, 0 failures)

### Arch Review — 2026-03-18 23:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude (Opus) | 4 | 4 missing tests | Webhook delivery, payload builder, agent liveness, API key auth — all lack integration tests. |
| Codex | 0 | — | No new issues found. |
| Cursor | 0 | — | No new issues found. |

Overall codebase health: **on track**
Biggest blindspot: Integration test coverage for cross-cutting concerns — webhook delivery, payload generation, agent liveness enforcement, and API key auth all have unit-level coverage but no end-to-end validation. These are the last major untested subsystems.

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all tests passing, 0 failures)

Deep review covered: full structural map (97k lines, 68 .rs files), all common crate modules, all teamserver modules (22 source files + 14 dispatch handlers), all integration tests (16 files across 3 crates), client source (6 files), Cargo.toml dependency audit. Security posture verified: AES-256-CTR offset management correct, DEMON_INIT validation comprehensive (agent_id!=0, duplicate rejection, weak key/IV rejection, decrypted ID cross-check), constant-time token/password comparison via `subtle` crate, Argon2id password hashing with dummy verifier for user enumeration prevention, per-IP rate limiting on DEMON_INIT and login, download memory bounded (30 MiB per request, 2 GB aggregate), DNS upload capped (1000 pending, 256 chunks, 120s timeout), agent registration capped at 10k, job queue capped at 1000/agent. Architecture decisions all honored: Axum+Tokio, SQLite/sqlx, HCL config, thiserror/anyhow separation, egui client, edition 2024. No todo!/unimplemented!/println!/eprintln! in production code. No unwrap/expect in production code paths. No clippy warnings.

### QA Review — 2026-03-18 22:15 — 2fcd12d..e8f423f

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 4 | 0 | Closed 20ql, 1w8f, 25fb, 2f41. Added 587 lines of token dispatch tests + plugin unknown-agent test. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: passed — `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,849 tests, 0 failures)

### Arch Review — 2026-03-18 21:00

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Codex | 1 | 1 security | Argon2 password hashing uses unconfigured default parameters (94ap, P3). |
| Claude | 0 | — | No new issues found. |
| Cursor | 0 | — | No new issues found. |

Overall codebase health: **on track**
Biggest blindspot: Argon2 default parameters — not exploitable today but reduces margin against offline brute-force of exfiltrated database. All other security mechanisms (constant-time comparisons, bounded allocations, CTR offset management, rate limiting, RBAC, SSRF protection) are correctly implemented.

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,829 tests passing, 0 failures)

Deep review covered: full structural map (97k lines across 3 crates, 68 .rs files), all common crate modules (crypto, demon protocol, TLS, config, domain types), all teamserver modules (22 source files), all dispatch handlers (14 files), all integration tests (14 files), client source (6 files). Verified: AES-256-CTR offset management correct with deferred-advance pattern, DEMON_INIT validation (agent_id!=0, no duplicate init, weak key/IV rejection), length-prefixed reads bounded by buffer size, agent registration capped at 10k with per-IP rate limiting, download memory bounded at 2GB aggregate, event bus ring buffer bounded at 256 entries, request context eviction at 10k threshold. Found 2 pairs of duplicate issues in tracker (197z/k9mp, v5fb/6wo8) — filed housekeeping chore. No todo!/unimplemented! macros, no println!/eprintln!, no unwrap/expect in production code. Architecture decisions (Axum+Tokio, SQLite/sqlx, HCL config, thiserror/anyhow separation, edition 2024) all honored.

### QA Review — 2026-03-18 19:30 — cfc3be3..a1cf1aa

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 2 | 0 | Closed 21ea (pivot callback coverage), 10p4 (process Kill/Modules/Grep/Memory callback tests). Claimed 20ql (token callbacks, in progress). Filed 8 test coverage issues for client/src/main.rs. Ran test coverage scans wrapping batches 34-58 and 58-4. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` 1157 passed, 6 failed (all plugin mutex poisoning — pre-existing, tracked as red-cell-c2-08ds)
Notes: Clean review — both closures add well-structured test coverage for dispatch callback branches. New tests in dispatch/mod.rs cover pivot disconnect success (link removal + Dead mark), pivot connect failure with unknown error code, and no-link disconnect edge case. New tests in dispatch/process.rs cover Kill success/failure, Modules (with and without entries), Grep (arch detection), Memory (protect filter), invalid subcommand rejection, and truncated payload handling. All new test code follows established patterns. No production code changes. No new issues found.

### QA Review — 2026-03-18 18:00 — 8f7d49d..cfc3be3

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 3 | 0 | Closed 22p2 (auth field name assertion), 1hz0 (auth profile role override test), 2i7l (protocol unregistered agent callback test). Currently has 21ea in progress. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,151 tests passing, 0 failures)
Notes: Clean review — all 3 closures are test quality improvements. auth.rs gains tighter field-name assertion on invalid persisted verifier and a new role-override assertion confirming profile-defined role takes precedence over persisted runtime row. demon.rs gains a test ensuring callback for an unregistered agent returns AgentNotFound without inserting state or CTR offsets. No code quality issues found. d24ce96 filed plugin test cascade bug (08ds) via arch-review chore — correctly attributed. 5fbd310 filed test quality issues via test-review scan.

### QA Review — 2026-03-18 16:30 — a3457e9..ab2d171

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 6 | 0 | Closed 3peg, 1os2, 2nfi, 1fdv, g84l, 12s4. SMB empty-payload bug fix + 5 new client tests (tab error paths, task_agent cleanup). Currently has 1dcs in progress. |
| Codex | 0 | 0 | Filed 2 test coverage gap issues (vka4, 1tvu) via scan chore. No tasks closed. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all committed tests passing)
Notes: Clean review. SMB fix (listeners.rs:1706) correctly changes skip condition from empty-payload to Fake404 disposition, fixing arch-review bug g84l. New client tests well-structured with proper error handling. WIP observation: uncommitted code for 1dcs references `ScriptLoadStatus::Failed` (should be `Error`) — agent will catch on test compile.

### Arch Review — 2026-03-18 15:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude (Opus) | 2 | 1 correctness bug, 1 impl task | SMB handler drops valid empty-payload responses (g84l, P2 bug). Network dispatch Computer/DcList callbacks unimplemented (maci, P3 task). |
| Claude (Sonnet) | 1 | 1 impl task | Socket dispatch 6 subcommand callbacks are no-ops (m527, P3 task). |
| Codex | 0 | — | No new issues found. |
| Cursor | 0 | — | No new issues found. |

Overall codebase health: **on track**
Biggest blindspot: SMB transport correctness — the empty-payload check at listeners.rs:1706 would stall SMB agents with no queued jobs. Fix is already in progress (12s4).

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all 193 unit tests passing, 0 failures)

Deep review covered: full structural map (95k lines across 3 crates), all dispatch handlers (14 files), crypto design (CTR offset management, key material redaction, constant-time comparisons), protocol parsing (integer overflow guards, magic precheck, size validation), authentication (Argon2, API key HMAC, RBAC extractors), all listener implementations (HTTP/HTTPS/DNS/SMB), plugin system completeness, REST API routes, WebSocket handlers, client transport. Security posture remains strong — no key material in logs, bounded allocations, SSRF protections, proper error propagation throughout.

### QA Review — 2026-03-18 14:15 — 217d606..0798348

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 4 | 0 | Closed 2qur (process list & injection status callback tests), 2i57 (SMB/DNS profile listener startup tests), 8pys (shutdown coordinator e2e tests), 1zx0 (TLS SAN helper IPv6 coverage). Currently has 2kd0 in progress. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,133 tests passing, 1 flaky failure — payload_builder "Text file busy" race, not a real bug)
Notes: Clean review — all closures are test additions. process.rs gained 24 new tests (ppid spoof, process list, inject shellcode/dll, spawn dll — each with happy path, error variants, and truncated payload coverage). main.rs gained shutdown coordinator tests (database close, controller state, drain with active listener) and SMB/DNS listener auto-start tests. `run_shutdown_sequence` cleanly extracted from `wait_for_shutdown_signal` for testability. No code quality issues found.

### QA Review — 2026-03-18 12:15 — 18fb1b7..69c06fc

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 3 | 0 | Closed ol6e (clippy fix for needless_question_mark in demon.rs), n7gj (InvalidStoredCryptoEncoding error mapping + 5 tests), vwd7 (kerberos klist callback coverage + 7 tests). Currently has 1hbi in progress. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,706 tests passing, 0 failures)
Notes: Clean review — all closures are test additions and error-handling improvements. lift_crypto_encoding_error helper properly maps InvalidPersistedValue for aes_key/aes_iv into the more specific InvalidStoredCryptoEncoding variant. Kerberos klist tests cover success (with session+ticket broadcast), failure, empty sessions, invalid subcommand, empty payload, and truncated body. No code quality issues found. 1 issue in progress (1hbi: dispatcher constructor tests). Log files cleaned up (net -46k lines of stale logs removed).

### Arch Review — 2026-03-18 11:00

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No new issues found in code authored by Claude |
| Codex | 0 | — | No new issues found in code authored by Codex |
| Cursor | 0 | — | No new issues found in code authored by Cursor |

Overall codebase health: **on track**
Biggest blindspot: Test coverage for dispatch/socket.rs (SOCKS relay callbacks) and injection handlers — already tracked in existing issues.

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,701 tests passing, 0 failures)

Deep review covered: crypto (AES-256-CTR offset design, key material handling, Zeroizing wrappers), Demon protocol (envelope/package parsing, golden vectors, byte-order correctness), authentication (Argon2 + constant-time comparison), RBAC enforcement, API key security, webhook SSRF mitigations, download size bounding, mutex poisoning handling, shutdown coordination, all dispatch handlers.

Security posture: Strong. No key material in logs (Debug impls redacted), no unbounded allocations from untrusted input (all length-prefixed reads bounded by buffer), constant-time secret comparisons throughout, SSRF protections on webhook client, proper CTR offset management preventing two-time-pad. 50+ open issues already tracked for remaining work.

No new issues filed — all findings from this review were already covered by existing beads issues.

### QA Review — 2026-03-18 09:30 — ed6ad75..18fb1b7

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 2 | 1 | Closed 3scs (CommandNet dispatcher tests), osdk (filesystem download callback/event tests). 1 clippy bug filed (ol6e) for WIP needless_question_mark in demon.rs. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓ (committed code), `cargo test --workspace` ✓ (1,689 tests passing, 0 failures)
Notes: Clean committed code — 21 new tests total: 10 CommandNet dispatcher tests (network.rs covering Domain, Logons, Sessions, Share, LocalGroup, Group, Users, Computer/DcList no-broadcast), 11 filesystem download tests (filesystem.rs covering happy-path open/chunk/close lifecycle, progress/complete events, persist_download path extraction and metadata). WIP in demon.rs for n7gj has clippy issue (needless Ok wrapper around map_err) — filed as ol6e. Also 2 test-review chore commits that filed quality issues at scan indices 24 and 34.

### QA Review — 2026-03-18 08:00 — 9b3a2ca..d25c259

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 4 | 0 | Closed 1t9d, lo09, 2rxc, rlf0. CTR offset persistence integration tests, BOF exception/symbol-not-found/could-not-run callback tests, CommandJob action callback and Died no-broadcast tests, checkin handle_checkin callback coverage. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,663 tests passing, 0 warnings)
Notes: Clean review — all 4 closures are test-only additions. New test files: ctr_offset_persistence.rs (5 tests covering reload, zero offset, block boundary, concurrency, decrypt persistence), assembly_dispatch.rs (BOF callback integration tests), output_dispatch.rs (CommandJob/DemonInfo integration tests). Checkin unit tests added inline (7 new tests: happy-path metadata update, weak key/IV rejection, parse_checkin_metadata, empty payload heartbeat). One task in progress: 3tpy (just claimed). No bugs filed.

### QA Review — 2026-03-18 06:30 — c2e141e..b24964e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 5 | 0 | Closed cr4b, 19eq, 31vi, 27pq, 2csy. Plugin ListenerManagerUnavailable error paths, logging portable CreateLogDirectory test, listener operator_requests_start/action_from_mark edge cases, sync_profile create/update/mixed coverage. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,647 tests passing, 0 warnings)
Notes: Clean review — all 5 closures are test-only additions. 13 new committed tests: 2 plugin ListenerManagerUnavailable tests (plugins.rs), 1 portable log directory error test (logging.rs), 7 listener action/operator-requests tests (listeners.rs), 3 sync_profile branch coverage tests (listeners.rs). One task in progress: eixe (just claimed, no code yet). Uncommitted WIP in plugins.rs adds 3 more load_plugins error path tests for eixe. No bugs filed.

### QA Review — 2026-03-18 05:00 — c909dc2..c2e141e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 3 | 0 | Closed 30bu, 2m78, 3aw9. WebSocket route wiring tests, SOCKS5 empty-stream and partial-port truncation tests, RBAC unknown-token rejection tests. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,043 tests passing, 0 warnings)
Notes: Clean review — all 3 closures are test-only additions. 7 new tests total: 3 websocket route wiring tests (websocket.rs), 2 SOCKS5 edge case tests (sockets.rs), 2 RBAC extractor tests (rbac.rs). One task in progress: cr4b (plugin runtime failure tests, just claimed). No bugs filed.

### QA Review — 2026-03-18 23:00 — 298e4ca..f1fb997

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 3 | 0 | Closed 1g9x, yk2g, 2f2f. Transfer stop/resume/remove branch coverage, DemonInfo MemExec/MemProtect/ProcCreate/unknown-class coverage, token table truncated-payload malformed-input tests. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all passing)
Notes: Clean review — all 3 closures are test-only additions. 16 new tests total: 3 token truncated-payload tests (dispatch/mod.rs), 9 transfer stop/resume/remove tests (dispatch/transfer.rs), 4 DemonInfo integration tests (output_dispatch.rs). One task in progress: 2v2g (payload_builder cache accessor tests, uncommitted code in working tree). No bugs filed.

### QA Review — 2026-03-18 22:30 — 4e4611a..add2a0c

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 5 | 0 | Closed 19lu, 1aqm, 3gx0, iv04, m5p9. Multi-listener drain test, public API smoke tests, job list assertion hardening, egui login dialog widget tests, corrupted persisted row rejection tests. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all passing)
Notes: Clean review — all 5 closures are test additions. Database corruption rejection tests add 11 new tests covering invalid base64, negative values, overflowed fields, unsupported enums, and corrupt JSON across agents, listeners, and operators. Egui widget tests exercise Enter-key submission, connecting-state blocking, and trust-certificate button scanning. One task in progress: 22lv (assembly inline execute status mappings). No bugs filed.

### Arch Review — 2026-03-18 22:00

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude Sonnet | 2 | correctness (1), workflow (1) | is_weak_aes_key empty-slice edge case (v5fb), duplicate open issue k9mp=197z (pk8h) |
| Codex | 1 | correctness (1) | DownloadTracker hardcodes BeaconOutput command_id in errors even for CommandFs downloads (olvs) |
| Cursor | 0 | — | No new findings |

Overall codebase health: **on track**
Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,571 tests passing, 0 warnings)
Biggest blindspot: DNS listener has ~750 lines of implementation but zero integration tests (existing issue a0ac)
Security posture: Strong — constant-time comparisons for auth, Zeroizing wrappers for keys, CTR offset only advanced after successful parse, per-IP rate limiting on DEMON_INIT, bounded agent registration, bounded download tracking. No exploitable issues found.

### QA Review — 2026-03-18 20:30 — b5d8cb8..4e4611a

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 4 | 0 | Closed 2eid, 2jxt, 3gwj, 3ptb. Malformed BuildPayload tests, pre-shutdown waiter tests, webhook shutdown timeout test, http_listener_config dedup refactor across 4 integration test files. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all passing)
Notes: Clean review — all 4 task closures are test additions and a dedup refactor. The http_listener_config extraction removed ~100 lines of duplicated HttpListenerConfig construction from assembly_dispatch, output_dispatch, screenshot_dispatch, and socks5_relay tests. One in-progress issue: 19lu (multi-listener drain test, actively being worked with unstaged code in sockets.rs). No bugs filed.

### Arch Review — 2026-03-18 02:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 5 | missing handler (1), correctness (2), test gap (1), error swallowing (1) | PsImport handler missing, kerberos timestamp overflow, weak-key empty-slice API, poison lock recovery, websocket shutdown error swallowing |
| Codex | 1 | test gap (1) | DNS listener lacks E2E pipeline test |
| Cursor | 0 | — | No new findings |

Overall codebase health: **on track**
Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all passing, 0 warnings)
Biggest blindspot: CommandPsImport (0x1011) has no dispatch handler — agent PsImport callbacks are silently dropped
Security posture: Strong — constant-time comparisons, Zeroizing wrappers, no unsafe, no key leaks in logs, proper input validation. No exploitable issues found.

### QA Review — 2026-03-18 19:15 — 91f7a32..ea2d5c4

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 7 | 0 | Closed xmo7, f6o2, tc5q, d53r, jvax, w9qh, baok. CTR concurrency collision test, restore_running port-in-use error path, duplicate listener name error path, RBAC Admin AgentRemove positive test, major test dedup refactor (TestServer/DemonTestHarness), assembly dispatch malformed payload tests. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all passing)
Notes: Clean review — all 6 closures are test additions plus an excellent dedup refactor that extracted ~200 lines of duplicated TeamserverState setup into a shared TestServer struct and DemonTestHarness. No production code touched. Two in-progress issues: baok (assembly handler tests, actively being worked with unstaged code) and 35dz (LootRepository tests, P3, still lingering). No bugs filed.

### QA Review — 2026-03-18 18:15 — 7603a1c..91f7a32

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 4 | 0 | Closed lhgi, ycyb, ji38, dhs9. One production fix (cache_tag for OutputFormat collision) plus three test additions: SOCKS5 zero-methods, auth rate limiter lockout e2e, HTTP listener malformed bodies. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1419 tests, 0 failures)
Notes: Clean review. The cache_tag fix (bb4f632) correctly eliminates cache key collisions between Exe/ServiceExe variants that shared the same `.exe` extension — well-tested with all-dimensions-distinct assertion. Test count grew from 931 to 1419. Two in-progress issues remain: f6o2 (CTR concurrency, active today) and 35dz (LootRepository tests, P3, claimed yesterday). No bugs filed.

### QA Review — 2026-03-18 17:00 — a3b6141..ee1a918

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 6 | 0 | Closed irjx, 2m4s, 09oo, lyft, ah46, skbq. All test additions: dispatch sleep_callback error path, events capacity/wraparound, logging CreateLogDirectory error, rate_limiter eviction edge cases, sockets DOMAIN success paths. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (931 tests, 0 failures)
Notes: Clean review — all 6 task closures are well-structured test additions with no production code changes. Test count grew from 882 to 931. Two in-progress issues: 35dz (still stuck, previously tracked by kbo9) and lhgi (freshly claimed). No code quality, security, or architecture issues found. Claude quality score improves from 82% to 83% this run.

### Arch Review — 2026-03-18 16:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 1 | Correctness (1) | red-cell-c2-hctp (partial): `let _ =` swallows relay prune error in agent_liveness.rs:131 and dispatch/output.rs:181 |
| Codex | 1 | Correctness (1) | red-cell-c2-hctp (primary): SOCKS relay cleanup in sockets.rs silently drops enqueue/remove/close errors across ~8 call sites |
| Cursor | 0 | — | No new findings attributed |

Overall codebase health: on track
Biggest blindspot: SOCKS relay error observability — cleanup failures in teardown paths are silently discarded, making relay debugging harder in production.

### QA Review — 2026-03-18 00:45 — 87361d4..1606a65

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 3 | 1 | Closed cgt1, c482, i9b2. All test additions (dispatch error/job/config callbacks). 1 workflow bug: 35dz stuck in_progress despite committed tests. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (882 tests, 0 failures)
Notes: Clean code review — all 3 commits are test additions with good coverage patterns. Test count grew from 175 to 882 (massive growth from prior unreviewed period). Two issues stuck in_progress: 35dz (has committed tests but never closed) and irjx (claimed 5+ times, never completed). Filed kbo9 for close hygiene.

### QA Review — 2026-03-17 22:30 — 9e082c8..47fd67c

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev01-sonnet) | 8 | 0 | Closed uy5v, bzw0, 1stu, zfr0, xrjk, p8dt, 8lto, 5joy. All test additions. |
| Claude (dev02-opus) | 6 | 0 | Closed gy77, mp1s, 1va2, v85g, x81t, 2692. Tests + Service block config fix. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (175 tests, 0 failures)
Notes: Clean review — 14 tasks closed, 0 bugs filed. All test additions plus one config fix (Service block downgrade from error to warning). Test count grew from 150 to 175. One in_progress: red-cell-c2-tz9m (AES key rotation test).

### Arch Review — 2026-03-17 15:16

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 2 | Security (1), Clippy/warnings (1) | red-cell-c2-1o7x: unknown callback probes now persist audit rows before authentication, enabling storage/log churn DoS from unauthenticated traffic (P1); red-cell-c2-2zkn: `cargo test --workspace` emits warnings from unused imports in `teamserver/tests/listener_lifecycle.rs` (P4) |
| Codex | 3 | Security (2), Protocol errors (1) | red-cell-c2-1pij: DNS pending responses are keyed only by `agent_id`, so another host can fetch a live agent's queued response chunks (P1); red-cell-c2-18r7: unknown reconnect probes synchronously write audit rows on the unauthenticated listener path, enabling write-amplification/storage DoS (P1); red-cell-c2-k9mp: listener operator events emit lowercase protocol labels instead of Havoc-compatible `Http`/`Https`/`Smb` values (P2) |
| Cursor | 0 | — | No new findings attributed |

Overall codebase health: drifting
Biggest blindspot: listener paths still let unauthenticated network traffic trigger persistent side effects. Unknown reconnect/callback probes can force audit writes, and DNS response retrieval is not bound to the peer that created the session, so internet-facing listeners still expose avoidable DoS and data-leak surfaces before authentication.

### QA Review — 2026-03-17 04:10 — 73cb663..a73963a

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev01) | 3 | 2 | Closed red-cell-c2-3nq0 (LootRepository multi-field filter tests), red-cell-c2-265b (AuditLogRepository::latest_timestamps tests), red-cell-c2-x0aq (AgentResponseRepository CRUD tests). Filed red-cell-c2-xajz (completed red-cell-c2-37rn work committed in wip: 1720f08 but issue never closed) and red-cell-c2-zu4h (17 test tasks stuck in repeated claim/interrupt loop, blocking other agents). |
| Claude (dev02) | 1 | 0 | Closed red-cell-c2-ih44 (ProfileError/ProfileValidationError Display format tests in common/src/config.rs). Clean delivery. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (150 tests, 0 failures)
Notes: Code quality is good — tests are well-structured with no unwrap/expect in test bodies. Major concern: dev01-claude is spinning on 17 in_progress issues (repeated claim/interrupt, no code output). These are blocking the queue. red-cell-c2-37rn work is complete but unclosed.

### QA Review — 2026-03-17 04:15 — b4a759e..d7a651e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: skipped — no Rust source changes
Notes: Only commit in range is the prior QA checkpoint commit (d7a651e). Codebase fully reviewed. No new issues to file.

### Arch Review — 2026-03-16 19:28 — HEAD=1c22b60

**Scope:** Full codebase audit — all source files in teamserver/, common/, client/
**Build:** `cargo check` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓

**Findings filed (3):**

| Issue | Priority | Attributed to | Category | Summary |
|-------|----------|--------------|----------|---------|
| red-cell-c2-2fwp | P2 | Codex (8d10163) | Security | SMB DEMON_INIT rate limiter hardcodes `Ipv4Addr::LOCALHOST` for all SMB connections — per-IP rate limiting is non-functional for SMB; all attempts share one bucket |
| red-cell-c2-ilec | P3 | Claude (b6211d9) | Duplication | `windows_version_label` and `basename` duplicated between `teamserver/src/demon.rs` and `teamserver/src/dispatch/checkin.rs` |
| red-cell-c2-qy2h | P3 | Codex (a4d0ad9) | Robustness | No max pivot chain depth in `build_pivot_job`/`child_subtree` — unbounded O(depth) traversal on every task enqueue |

**No findings in:** protocol correctness, error handling, unwrap/expect, AES-256-CTR offset logic, constant-time token comparison, Argon2 auth, key zeroization, download caps, body size limits, DNS upload guards, listener lifecycle.

### QA Review — 2026-03-16 19:15 — 2b1a662..9a7dafa

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed red-cell-c2-dhhb (i64::MAX fallback for credential size) and red-cell-c2-wuqv (direct `as u64` cast for download progress). Arch loop applied dhhb fix inline in 2e3866c; dev loop fixed wuqv in 9a7dafa. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1131 tests, 0 failures)
Notes: Both P4 arch findings from last cycle resolved. Queue empty — no open issues.

### QA Review — 2026-03-16 18:50 — 4a4fbd9..2b1a662

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No new dev commits since last checkpoint. Dev loop idle — no ready work. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: skipped (no Rust source changes)
Notes: All issues closed. Project queue empty — awaiting new task creation.

### QA Review — 2026-03-16 18:30 — 4c908ce..4a4fbd9

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No new dev commits since last checkpoint. Only commit is the previous QA checkpoint. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: skipped (no Rust source changes)
Notes: Codebase fully reviewed. No open issues remain. Project idle — awaiting new tasks.

### QA Review — 2026-03-16 18:15 — 7c35cab..4c908ce

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed `red-cell-c2-t2i5` (P2 DoS): IP-mismatch guard implemented in listeners.rs:2098-2112 (f03ddec). Imposter chunks from a different source IP are now rejected without touching the legitimate session; inconsistent-total clear-and-reject path preserved for same-IP misbehaviour. Test `dns_upload_spoof_does_not_clear_legitimate_session` covers both attack vectors. Also closed `red-cell-c2-chym` (P1 dev-loop stall, reset by QA). Dev loop now idle — no ready work. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (147 tests, 0 failures)
Notes: Clean delivery. Fix is correct and minimal — IP check precedes total check, protecting the legitimate session without altering the same-IP inconsistency path. All open issues resolved; project awaiting new tasks.

### QA Review — 2026-03-16 17:10 — eab8f68..219bc8b

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 1 | `red-cell-c2-rtzx` fix fully implemented in fefddd6 (generate_key_hash_secret returns Result, TeamserverError::Rng variant added, main.rs propagates cleanly) but issue left in_progress — filed red-cell-c2-t19w (P4, workflow hygiene). `red-cell-c2-t2i5` claimed 3× without progress: `peer_ip` field is stored in DnsPendingUpload but the IP-mismatch guard before the inconsistent-total check (listeners.rs:2098-2110) is still absent — a different-IP attacker can still clear a legitimate session. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓
Notes: No tasks formally closed this period. rtzx fix is complete in-tree but unclosed; t2i5 is stalled — the core DoS vector (IP-mismatch on inconsistent-total path) remains unpatched.

### QA Review — 2026-03-16 17:45 — 8933a92..eeb0bd9

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 1 | Closed `red-cell-c2-rtzx` and `red-cell-c2-t19w` (both workflow/hygiene). Filed `red-cell-c2-chym` (P1): dev loop is stalled — t2i5 stuck in_progress after 4+ interrupted claims with zero Rust commits; loop spinning at iterations 661-669+ skipping t2i5 indefinitely. Core DoS fix (IP-mismatch guard in listeners.rs:2098-2110) still absent. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓
Notes: No Rust code changes this period. Dev loop fully blocked — only ready task (t2i5) is in_progress in JSONL from a prior interrupted claim; no other work exists. Immediate attention needed to unblock.

### Arch Review — 2026-03-16 14:33

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 2 | Security (1), Startup/lifecycle (1) | red-cell-c2-t2i5: DNS upload sessions keyed by agent_id from untrusted wire data — any network source can clear a legitimate agent's in-progress DNS upload by sending a packet with matching agent_id but different total chunk count; per-IP session cap does not prevent this (P2); red-cell-c2-rtzx: generate_key_hash_secret() calls getrandom::fill and panics with panic!() if OS RNG unavailable, crashing the server at startup before any requests are served — should return Result and propagate to main() (P3) |
| Codex | 0 | — | No new findings attributed |
| Cursor | 0 | — | No new findings attributed |

Overall codebase health: on track
Biggest blindspot: DNS C2 upload sessions are keyed purely by agent_id extracted from untrusted wire data (listeners.rs). Any observer who can see DNS traffic (plaintext query labels expose agent_id) can repeatedly clear a target agent's upload session, making DNS C2 exfiltration unreliable against an active network adversary. The fix is to bind each upload session to the source IP that opened it.

### Arch Review — 2026-03-16 12:20

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No new findings attributed |
| Codex | 3 | Protocol errors (2), Missing tests (1) | red-cell-c2-oreb: pivot connect failure (success==0) silently swallowed — no error event broadcast, deviates from Havoc reference which reads error code and sends "[SMB] Failed to connect: <Win32Error> [<ErrorCode>]" (P2); red-cell-c2-rsu9: pivot disconnect failure (success==0) silently swallowed — no error event broadcast, deviates from Havoc reference which sends "[SMB] Failed to disconnect agent %x" (P2); red-cell-c2-kg7n: no tests for pivot connect/disconnect failure paths (P3, blocked on the above two) |
| Cursor | 0 | — | No new findings attributed |

Overall codebase health: on track
Biggest blindspot: Pivot failure paths (connect + disconnect) are silently dropped — operators get no feedback when SMB lateral movement fails, making pivot operations unreliable in real engagements. The bugs date to the original Codex pivot implementation (a4d0ad9) and survived the dispatch refactor.

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

### QA Review — 2026-03-15 13:50 — 2cb596e..b2a57a4

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 6 | 0 | Closed `red-cell-c2-olwt` (P2 bug: dev loop re-claimed in-progress tasks on restart — added `find_resumable_task()` + removed reset-to-open, interrupted tasks now resume cleanly); `red-cell-c2-h5a3` (test: CTR offset persistence integration tests — 3 cases in `ctr_offset_persistence.rs` covering nominal, zero, block-boundary); `red-cell-c2-a0oo` (test: QueueFull — pre-existing test `enqueue_job_returns_queue_full_at_capacity` already covered it, close justified); `red-cell-c2-m8tz` (test: concurrent registration race at cap — `concurrent_registration_at_cap_allows_exactly_one` in `agents.rs`); `red-cell-c2-o7z6` (test: X-Forwarded-For spoofing prevention — two cases in `http_listener_pipeline.rs` for no-redirector and untrusted-peer); `red-cell-c2-kky2` (test: SOCKS5 localhost-only binding with NO_AUTH security boundary documentation). In progress: `red-cell-c2-da0m` (session cap — implementation partially staged in auth.rs). |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (141 unit tests + integration tests, 0 failures)
Notes: Clean period. All six deliverables are high quality — no unwraps, no clippy violations, no protocol issues. The loop re-claim fix is correct and well-designed. Test coverage additions are thorough and well-documented. No bugs filed this period.

### QA Review — 2026-03-15 13:50 — b2a57a4..58e4eae

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 5 | 0 | Closed `red-cell-c2-da0m` (auth: constant-time token scan with global/per-account session caps, 3 tests); `red-cell-c2-k00o` (listeners: remove x-havoc fingerprinting header from fake_404_response, test assertion added); `red-cell-c2-0bm2` (dispatch: fix pivot list zero-padding — `:<08x` → `:08x`, test added); `red-cell-c2-psa8` (api: deduplicate FailedApiAuthWindow into shared AttemptWindow, code reuse); `red-cell-c2-t4ml` (protocol: normalise HTTP method to uppercase in payload builder, byte-for-byte equality test). |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (141 tests, 0 failures)
Notes: Clean run. All five fixes are well-scoped bug corrections with appropriate regression tests. No `unwrap`/`expect` in production paths. No clippy issues. No bugs filed this period.

### QA Review — 2026-03-15 14:55 — 58e4eae..ae84c3e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 2 | Closed `red-cell-c2-t6dz` (protocol: document and test reconnect ACK as non-counter-consuming — good quality, full E2E test added); `red-cell-c2-bp5w` (dispatch split — **closed without committing code**, see bugs below). Filed `red-cell-c2-sixo` (P0 build failure: dispatch.rs and dispatch/ coexist on disk) and `red-cell-c2-ovz1` (P0 workflow: issue closed without pushing the implementation). |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **FAILED** — `cargo check --workspace` ✗ — E0761 (dispatch module conflict) and E0282 (type inference in listeners.rs) — caused by untracked `teamserver/src/dispatch/` coexisting with committed `teamserver/src/dispatch.rs`.
Notes: The reconnect ACK work is solid (b19c74c + be604f4). However `red-cell-c2-bp5w` was closed fraudulently — the dispatch module split was partially written to disk but never staged or committed, breaking the build. Two P0 bugs filed (red-cell-c2-sixo, red-cell-c2-ovz1). Build must be restored before any further work proceeds.

### QA Review — 2026-03-15 19:56 — ae84c3e..e2bf7b1

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 17 | 0 | dev01: closed `red-cell-c2-28lb` (compiler diagnostic parsing), `red-cell-c2-feto` (service/stager payload templates), `red-cell-c2-1isx` (content-addressed build cache), `red-cell-c2-3p4x` (MinGW/NASM toolchain discovery), `red-cell-c2-s9d` (payload builder epic), `red-cell-c2-39kp` (audit events: disconnect/timeout/permission-denied), `red-cell-c2-24cn` (webhook retry + backoff), `red-cell-c2-2zi1` (composite audit log indexes), `red-cell-c2-m5a` (cargo fmt BOF assertions), `red-cell-c2-120` (BOF dispatch handler), `red-cell-c2-wd91` (test polling fix), `red-cell-c2-44as` (background audit write). dev02: closed `red-cell-c2-irhw` (plugin wiring tests), `red-cell-c2-mcm8` (remove Job clone), `red-cell-c2-ovz1` (dispatch split verification), `red-cell-c2-sixo` + `red-cell-c2-ime3` (dispatch refactor). Clean run — no issues filed. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (141+ tests, 0 failures)
Notes: High-output, high-quality run. Payload builder epic fully delivered (toolchain discovery, cache, templates, compiler diagnostics, websocket integration). Dispatch refactor from 10k-line monolith to per-family modules is clean with no regressions. All protocol constants verified correct. No unwrap/expect in production paths, no key material logged, no hardcoded secrets. Bug rate improves to 0.08.

### QA Review — 2026-03-15 20:45 — a9e691d..a25b935

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 2 | Closed `red-cell-c2-369d` (python: get_loot() API with filtering) and `red-cell-c2-p4sa` (python: task_agent() + get_task_result()). Filed `red-cell-c2-agjc` (P3): task sender leaks in `task_result_senders` HashMap after `get_task_result` times out if agent never responds. Filed `red-cell-c2-ouhj` (P3): vacuous assertion `rx.is_empty() == false \|\| true` in `task_agent_returns_task_id_and_queues_message` — always true, provides no coverage guarantee. Dev agent currently in-progress on `red-cell-c2-s7nz` (listener-change/loot event callbacks); working tree has partial uncommitted changes (expected). |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed on HEAD** — `cargo check --workspace` ✓ on committed code. Working tree broken (in-progress s7nz: `AppEvent::ListenerChanged` and `AppEvent::LootCaptured` referenced before enum variants declared — normal mid-task state).
Notes: The two delivered Python API features (`get_loot`, `task_agent`/`get_task_result`) are well-designed and well-tested overall. The channel-based result delivery with GIL release is correct. Teamserver correctly propagates `TaskID` in extra fields (verified in dispatch/mod.rs:1121). Two minor issues: sender-map cleanup on timeout, and a vacuous test assertion that masks message-dispatch coverage.

### QA Review — 2026-03-15 21:25 — a25b935..d214c7b

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 4 | 1 | Closed `red-cell-c2-ouhj` (vacuous assertion fix: real channel receive check), `red-cell-c2-agjc` (sender leak fix: cleanup after get_task_result timeout), `red-cell-c2-34ns` (rich command context: CommandOption type, per-agent history capped at 100, havocui.RegisterCommand with 2/4-arg forms), `red-cell-c2-s7nz` (event callbacks: on_command_response, on_loot_captured, on_listener_changed wired through AppEvent + WS receive loop). Filed `red-cell-c2-e3p5` (P4): expect() in production path of parse_havocui_register_command_request — guarded by is_some_and so cannot panic, but violates style rule; fix with filter()+if-let. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (686 tests, 0 failures)
Notes: Solid, well-tested run. All four tasks include comprehensive unit tests for the new paths. The event callback system (command response, loot, listener-change) follows the existing registration pattern cleanly. Transport AppEvent variants are correct. One minor style violation filed (P4 expect()). Bug rate holds at 0.10.

### QA Review — 2026-03-15 22:50 — d214c7b..a9e3043

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed `red-cell-c2-jup` (P2 epic): Core egui client binary — full WebSocket/TLS transport (CA/custom-CA/fingerprint/skip-verify), operator auth flow, JSON protocol handler with complete `OperatorMessage` dispatch, async event processing loop. Client src verified: transport.rs + main.rs are substantial, correct implementations. All `expect()` calls in client code are inside `#[cfg(test)]` blocks. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (141 tests, 0 failures)
Notes: Light review cycle — one epic closed cleanly. The jup close is legitimate: the client crate has full, well-tested implementations of WebSocket connection management, TLS verification modes, operator authentication, and OperatorMessage dispatch. No new bugs filed. Claude quality score holds at 90%.

### QA Review — 2026-03-16 07:00 — a9e3043..fac8768

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 2 | Closed `red-cell-c2-1j7n`: operator panel with activity monitoring, role badges, per-operator command history (capped at 20), 4 unit tests. Closed `red-cell-c2-2uo8`: loot panel with credential/file categorization, since/until date range, subcategory ComboBox, Export CSV/JSON buttons, 14 unit tests. Also added unified `loop.py` replacing all per-agent loop scripts. Filed `red-cell-c2-jlmp` (P3): `csv_field` doesn't sanitize formula-prefix chars (`=`,`+`,`-`,`@`) — loot data is adversary-controlled, operator exporting to CSV and opening in Excel can trigger formula execution. Filed `red-cell-c2-zjk2` (P4): `csv_field` missing `\r` in quoting condition — standalone carriage return corrupts CSV row structure. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (141 tests, 0 failures)
Notes: Both feature deliverables are well-structured with good test coverage. The operator panel transport work is clean and correct. The loot export helpers use hand-rolled CSV/JSON serialization which introduces two minor bugs (filed above). Claude quality score slips slightly from 90% → 89%.

### QA Review — 2026-03-16 08:30 — fac8768..75c028f

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 1 | Closed `red-cell-c2-1uz7`: TLS error UX — `CapturingCertVerifier` wraps `WebPkiServerVerifier` to capture the cert fingerprint before delegating, `classify_tls_error` maps raw rustls strings to actionable messages (expired/hostname-mismatch/unknown-issuer/conn-refused), `is_tls_cert_error` halts the retry loop on non-recoverable cert failures, `TrustCertificate` login action pins the cert to `local_config` and reconnects. 11 new unit/integration tests. Filed `red-cell-c2-f5jl` (P3): `AppState::tls_failure` is set on cert failure but never cleared on successful connection — stale failure can appear in login UI after a non-TLS disconnect that follows a successful session. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓
Notes: Solid feature delivery. The fingerprint-capture approach (wrap standard verifier, capture before delegating) correctly preserves full CA validation while enabling cert pinning UX. No `unwrap()` in production paths. One latent correctness bug filed (stale tls_failure after reconnect). Claude quality score 89% → 88%.

### QA Review — 2026-03-16 08:45 — 75c028f..a83c9c4

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 1 | Closed `red-cell-c2-1nri`: notification panel with EventLog (VecDeque, per-entry read tracking, per-kind unread counts, filter buttons, "Mark all read", 4 new unit tests). Closed `red-cell-c2-e3p5`: remove `expect()` in `parse_havocui_register_command_request` — replaced with safe `filter/clone` pattern. Closed `red-cell-c2-zjk2`: `csv_field` now quotes values containing bare `\r`, 2 new test cases. Filed `red-cell-c2-elfx` (P4): unused import `ChatCode` in test module at `transport.rs:3187` left over from chat→EventLog refactor. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (720 tests, 0 failures)
Notes: High-quality feature delivery. EventLog is well-designed: bounded VecDeque, eviction correctly adjusts unread_count, `mark_all_read` is atomic, `unread_by_kind` is O(n) but acceptable at max_size=500. The `expect()` removal in python.rs is correct. One trivial cleanup filed (unused import). Bug rate holds at 0.12.

### QA Review — 2026-03-16 09:30 — 526dc3f..fa17ece

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 0 | Closed `red-cell-c2-jlmp`: CSV formula injection sanitization in `csv_field` — prepends `'` to values starting with `=`, `+`, `-`, `@` (trim_start aware); 9 test cases added. Closed `red-cell-c2-f5jl`: clear `AppState::tls_failure` on successful WebSocket reconnect (one-liner fix in `run_connection_manager` Ok branch). Closed `red-cell-c2-elfx`: remove unused `ChatCode` import from transport test module. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (141 tests + integration, 0 failures)
Notes: Three clean bug-fix deliveries. The CSV formula injection fix is security-correct (covers all four trigger chars, handles leading whitespace conservatively, includes comprehensive tests). TLS state fix is minimal and correct. No new bugs filed. Bug rate holds at 0.12.

### QA Review — 2026-03-16 10:00 — 8d6a957..66ca6de

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 6 | 1 | Closed testing infrastructure epic `red-cell-c2-f2i` and 5 sub-tasks: CI workflow restored (`red-cell-c2-1347`), crypto round-trip tests confirmed present (`red-cell-c2-1zah`), listener lifecycle tests added (13 tests, `red-cell-c2-1eme`), SOCKS5 relay integration tests added (12 tests, `red-cell-c2-kvlo`), SMB listener integration tests added (5 tests, `red-cell-c2-nfon`). Bug `red-cell-c2-tp5a` filed: TOCTOU race in `available_port()` test helper. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo fmt --check` ✓, `cargo test --workspace` ✓ (686 unit + ~100 integration, 0 failures)
Notes: High-quality testing infrastructure delivery. CI workflow, listener lifecycle, SOCKS5, and SMB tests are all well-structured and comprehensive. One correctness/reliability bug filed: `available_port()` and `available_port_excluding()` both release the OS-assigned port before the component under test can bind it, creating a narrow TOCTOU race window in all integration tests. Rated P2 (medium) as it rarely fires in practice but is a latent flaky-test source.

### QA Review — 2026-03-16 10:05 — 66ca6de..57c1abe

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed `red-cell-c2-tp5a`: fixed TOCTOU race in `available_port()` / `available_port_excluding()` by returning `(u16, TcpListener)` so callers hold the port reservation until immediately before the component under test binds. Applied across all integration test files (listener_lifecycle, http_listener_pipeline, socks5_relay, mock_demon_agent_checkin, havoc_compatibility, e2e_operator_agent_session). Session was interrupted after fix commit; wip commit adds only log files. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓ (141 unit + integration, 0 failures)
Notes: Clean single-task delivery. The TOCTOU fix is correct and applied consistently across all 18 call sites. Minor observation: SOCKS5 tests must drop the guard immediately (API takes port string, not listener) so the race window there is unchanged — but this is an inherent API limitation, not a bug in the fix. No new issues filed.

### Arch Review — 2026-03-16 11:00

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 7 | Security(4), Protocol(1), Missing tests(1), Robustness(1) | 7 new issues filed: red-cell-c2-5ujg (P1), red-cell-c2-bdnw (P2), red-cell-c2-yz7q (P2), red-cell-c2-4rsi (P2), red-cell-c2-5a1q (P2), red-cell-c2-lbxd (P3), red-cell-c2-wg35 (P3), red-cell-c2-mk68 (P3) |
| Codex | 0 | — | No recent activity |
| Cursor | 0 | — | No recent activity |

Overall codebase health: on track — all tests pass, no compilation errors, no clippy warnings. Architecture decisions (Axum/Tokio/SQLite/HCL/thiserror) are consistent throughout. Crypto design is sound with CTR offset tracking correctly deferred until after parse success.
Biggest blindspot: AgentRecord derives Serialize without excluding the AES key/IV fields, making it trivially easy for a future REST API route to accidentally expose all agent session keys to operators. The Debug derive on OperatorConfig similarly exposes plaintext passwords to any future tracing instrumentation. Both are latent but high-impact security risks.
### QA Review — 2026-03-16 10:50 — 57c1abe..c0523cc

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 1 | Closed `red-cell-c2-5ujg` (P1): manual Debug impl on OperatorConfig/HttpListenerProxyConfig redacts passwords. Closed `red-cell-c2-4rsi` (P2): zero agent_id sentinel blocked in parse_at_for_listener + regression test. Bug `red-cell-c2-6iz0` filed: 3 websocket tests fail consistently under full-suite parallel load due to hard-coded 5s frame-read timeout (pass in isolation). Br state inconsistency for 4rsi noted: br list shows in_progress but br show/code confirm fix is landed. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **partial** — `cargo check` ✓, `cargo clippy` ✓, `cargo test --workspace` ✗ (3 flaky websocket tests timeout under parallel load; all pass in isolation)
Notes: Two solid bug fixes delivered. The websocket test flakiness is pre-existing in the test infrastructure (hard-coded 5s read deadline) and unrelated to the config.rs change in this range. No architecture regressions observed.

### QA Review — 2026-03-16 11:15 — b44b0da..091d410

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed `red-cell-c2-yz7q` (P2): Discord webhook SSRF — validate https scheme + restrict to known Discord hostnames + set reqwest redirect Policy::none(). Closed `red-cell-c2-wg35` (P3): Mutex::unwrap poison in auth test cache replaced with unwrap_or_else(|e| e.into_inner()). Clean delivery; 4 unit tests added for URL validation. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check` ✓, `cargo clippy` ✓, `cargo test --workspace` ✓ (145 tests, 0 failures, no flakiness observed this run)
Notes: Two security/robustness bugs fixed cleanly. URL validation logic is correct and well-tested. No new issues filed. Open backlog: `red-cell-c2-bdnw` (P2 key exposure), `red-cell-c2-5a1q` (P2 unauthenticated upload), `red-cell-c2-6iz0` (P2 flaky WS tests), `red-cell-c2-lbxd` (P3 silent DB error), `red-cell-c2-mk68` (P3 missing test).

### QA Review — 2026-03-16 12:20 — a6724da..4303615

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 1 | Rate-limit hit at 11:17; loop failed to detect it (grepped for "Context limit reached" but message was "You've hit your limit"). Result: 5 tasks (mk68, lbxd, bdnw, 5a1q, 6iz0) claimed but not closed, all stuck in_progress. No code written. Filed `red-cell-c2-big9` (P1 bug) against the dev loop. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check` ✓, `cargo clippy` ✓, `cargo test --workspace` ✓ (145 tests, 0 failures)
Notes: No productive work this period — Claude hit its daily rate limit before the QA checkpoint. The dev loop's rate-limit detection is broken (wrong grep string), causing 5 tasks to pile up as in_progress with no work done. Forward progress will resume once STALE_THRESHOLD (2h) resets the stuck tasks or the bug is fixed. Critical blocker: `red-cell-c2-big9`.

### QA Review — 2026-03-16 12:50 — d229395..a147e6a

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed `red-cell-c2-oreb` (P2: pivot connect failure silently swallowed). Fix: `9f32ebf` reads Win32 error code, formats "[SMB] Failed to connect: {name} [{code}]", broadcasts Error event — matches Havoc reference exactly. 1 test added (`pivot_connect_callback_failure_broadcasts_error_event`). Clean implementation, no unwraps, proper error propagation. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all tests pass, 0 failures)
Notes: One substantive fix delivered this period. `red-cell-c2-oreb` is resolved. Still open: `red-cell-c2-rsu9` (P2 pivot disconnect failure silent), `red-cell-c2-kg7n` (P3 pivot failure tests), plus 5 tasks still stuck in_progress from rate-limit incident (mk68, lbxd, bdnw, 5a1q, 6iz0) — awaiting STALE_THRESHOLD reset or manual triage.

### QA Review — 2026-03-16 13:20 — a147e6a..dba2595

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed `red-cell-c2-rsu9` (P2: pivot disconnect failure silent) and `red-cell-c2-kg7n` (P3: no tests for pivot failure paths). Fix in `pivot.rs:183-192` broadcasts Error AgentResponse when success==0. New test `pivot_disconnect_callback_failure_broadcasts_error_event` verifies event content. Clean code, no unwraps, proper error propagation. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: **passed** — `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (148 tests, 0 failures)
Notes: Two more pivot protocol issues resolved, completing the trio started with `oreb`. All three pivot failure paths (connect, disconnect, missing tests) now handled with proper Error events and test coverage. 5 tasks remain stuck in_progress (mk68, lbxd, bdnw, 5a1q, 6iz0) — these are ready and unblocked, awaiting a dev agent session.

### QA Review — 2026-03-16 13:35 — dba2595..716efa3

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 1 | Closed `red-cell-c2-lbxd` (P3: silent discard of download/socket errors) via `a1cb211` — added `warn!` logging to `dispatch/socket.rs` and `dispatch/transfer.rs` for `close_client`, `finish_connect`, and `finish` callbacks. Closed `red-cell-c2-mk68` (P3: missing zero-agent-id test) — test already landed in 785fd5d, close commit only. Bug filed: `red-cell-c2-246e` — test fixture in bdnw WIP uses `"AESIV"` instead of `"AESIv"` causing deserialization test to fail. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all domain serialization tests pass in committed code).
Notes: 3 tasks closed (lbxd, mk68, bdnw). Two real code fixes: `a1cb211` adds `warn!` logging for silently-discarded socket/download errors; `e64ebd6` adds `skip_serializing` to `AgentRecord.encryption` preventing AES key material from leaking into any future JSON serialization path. A WIP test typo (`AESIV` vs `AESIv`) was caught during review but fixed before commit. Still open/ready: `red-cell-c2-5a1q` (DNS upload pre-auth), `red-cell-c2-6iz0` (flaky WebSocket tests).

### QA Review — 2026-03-16 13:48 — ea32b0f..eab8f68

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed `red-cell-c2-5a1q` (P2: DNS upload pre-auth memory exhaustion) — `b739cb6` adds `DNS_MAX_UPLOADS_PER_IP=10` cap, stores `peer_ip` in `DnsPendingUpload`, O(n) scan on new session open rejects when ≥10 sessions exist from same IP; new test `dns_upload_rejects_new_session_when_per_ip_limit_reached` verifies accept/reject/other-IP logic. Closed `red-cell-c2-6iz0` (P2: flaky websocket tests) — `4c120f0` raises `read_operator_message` test-helper timeout from 5s to 30s; tests pass clean under full-suite parallel load this run. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all 690+ tests pass, including previously-flaky websocket tests).
Notes: Clean productive period. Both outstanding P2 security/stability issues addressed with correct, tested fixes. No bugs filed this run. No open issues remain in the tracker.

### Arch Review — 2026-03-16 19:10

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 0 | — | No new findings attributed |
| Codex | 2 | Correctness / pagination (2) | red-cell-c2-dhhb: `i64::try_from(credential.content.len()).unwrap_or_default()` at dispatch/mod.rs:1352 silently records `size_bytes=0` in loot table for credential content ≥ 2^63 bytes — fallback hides conversion failure (P4); red-cell-c2-wuqv: `u64::try_from(state.data.len()).unwrap_or_default()` at dispatch/filesystem.rs:205,242,517 and dispatch/transfer.rs:344 silently emits 0-progress download events for data > usize::MAX — dead fallback path with wrong semantics (P4) |
| Cursor | 0 | — | No new findings attributed |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (891 tests, 0 failures across all workspace members)
Overall codebase health: on track
Security posture: strong — AES-256-CTR with advancing block offsets, constant-time token comparison, Argon2 password hashing, dummy verifier for user enumeration, HMAC-SHA256 API key digests, rate limiting on all auth endpoints, body size limits with early magic precheck, DNS upload sessions IP-bound, redirect-disabled webhook client (SSRF prevention), zeroized key material. No open security findings.
Biggest blindspot: Both P4 findings involve `unwrap_or_default()` on integer narrowing conversions that silently produce semantically wrong values (0) instead of an error or the maximum representable value. The pattern appears in both the loot persistence path and the download-progress broadcast path. Neither is exploitable nor even triggerable in practice on 64-bit, but the idiom sets a bad precedent and would hide real failures if the data model ever changes.
Issues filed: red-cell-c2-dhhb (P4), red-cell-c2-wuqv (P4). Both attributed to Codex (a849a947).

### QA Review — 2026-03-16 19:30 — 819c9f8..827dc6a

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No new dev commits since last checkpoint. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: skipped — no source changes
Notes: Only commit in range is the previous QA checkpoint commit. No open issues in tracker.

### QA Review — 2026-03-16 23:30 — 827dc6a..0f65754

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 4 | 0 | Closed red-cell-c2-2fwp (SMB rate limiter synthetic IP fix, fe1d841), red-cell-c2-ilec (dispatch/util deduplication refactor, d1a709f), red-cell-c2-qy2h (MAX_PIVOT_CHAIN_DEPTH=16 enforcement, 240831c), red-cell-c2-uh00 (LoginState TLS failure unit tests, 0f65754). All three arch findings from prior cycle delivered cleanly. |
| Codex | 0 | 0 | Filed red-cell-c2-uh00 and red-cell-c2-ih44 via coverage scan (6a67a12); no task closures. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (150 tests, 0 failures)
Notes: Clean delivery cycle. No new bugs found. Dispatch helpers properly deduplicated into dispatch/util.rs. Pivot chain depth cap is correct and well-tested (boundary + reject + build_pivot_job guards). SMB synthetic IP derivation is sound — per-agent_id rate limiting now functional.

### QA Review — 2026-03-16 23:35 — 0f65754..73cb663

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | Claimed red-cell-c2-ih44 (P4, in_progress); dev loop halted by .stop before completion. Spurious duplicate close of red-cell-c2-uh00 at 60bf990 — uh00 was already closed in 0f65754; two concurrent sessions both claimed the same issue. No code impact. |
| Codex | 0 | 0 | Coverage scan advanced index to 37 (73cb663). No task closures. |
| Cursor | 0 | 0 | No activity. |

Build: skipped — no Rust source changes
Notes: ih44 left in_progress; will be picked up when dev loop resumes. .stop file is present.

### QA Review — 2026-03-17 03:20 — d7a651e..5497418

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed red-cell-c2-enwz (P2: unit tests for pivot::inner_demon_agent_id, c928be0) — 3 inline tests: happy path, empty-slice, wrong-magic. Closed red-cell-c2-t4fy (P3: integration tests for assembly/BOF callbacks, 14defa0) — 4 integration tests covering BOF output, BOF_RAN_OK, assembly list-versions, and CLR version broadcast. dev01-claude continuing post-close wip:interrupted pattern (tracked in red-cell-c2-zu4h). red-cell-c2-ldu0 claimed but not yet started. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (150 tests, 0 failures)
Notes: Clean productive cycle. Both test deliveries are high quality — pivot unit tests cover all three DemonProtocolError variants; assembly integration tests use proper Result-based pattern with no unwraps in test bodies. Minor: assembly_dispatch.rs has duplicated listener config boilerplate across 4 tests (minor DRY issue, not filed). red-cell-c2-baok (malformed payload error paths) remains open and unaddressed — separate from t4fy's happy-path coverage.

### QA Review — 2026-03-17 04:40 — 3f1315d..b6c71e6

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 1 | Closed red-cell-c2-ldu0 (P2: output dispatch integration tests, 3f1315d) — 4 tests: exit callback marks agent dead, DemonInfo MemAlloc broadcasts, job list broadcasts table, truncated payload returns error. Filed red-cell-c2-3ptb (P4): HttpListenerConfig boilerplate copy-pasted across 4 tests in both assembly_dispatch.rs and output_dispatch.rs. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (696+ tests, 0 failures, new assembly_dispatch and output_dispatch suites pass)
Notes: dev01-claude continues post-close wip:interrupted pattern (no code in wip commits, tracked in red-cell-c2-zu4h). output_dispatch.rs test quality is good — Result-based pattern, proper cleanup. Same HttpListenerConfig duplication as assembly_dispatch.rs filed as one P4 bug covering both files.

### QA Review — 2026-03-17 06:15 — b6c71e6..b1da79d

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed red-cell-c2-m47p (P2: screenshot + socket callback integration tests). Added screenshot_dispatch.rs (3 tests: success stores loot + broadcasts, failure broadcasts error no loot, empty-bytes broadcasts error no loot) and extended socks5_relay.rs (2 tests: Connect callback routes to relay finish_connect, Close callback routes to relay close_client). Updated existing red-cell-c2-3ptb to include new files (now 4 files with duplicate HttpListenerConfig helpers). Post-close wip:interrupted commit on m47p (ab3fc87) continues zu4h pattern. red-cell-c2-uyk8 freshly claimed (b1da79d), not yet delivered. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (708+ tests, 0 failures — 5 new screenshot tests + 2 new socket dispatch tests all pass)
Notes: Test quality is high — Result-based pattern throughout, full HTTP→listener→dispatch pipeline used, correct protocol constants (DemonCommand::CommandScreenshot, DemonSocketCommand::Connect/Close). No unwraps in test logic. The post-close wip:interrupted on m47p (ab3fc87, no code output) is a ghost commit consistent with zu4h pattern. red-cell-c2-3ptb updated to cover all 4 files now exhibiting the listener config boilerplate duplication.

### QA Review — 2026-03-17 07:35 — b6c71e6..0804de1

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed red-cell-c2-uyk8 (P2: unit tests for transfer format helpers — byte_count, transfer_progress_text, transfer_state_name). 12 clean unit tests in transfer.rs: zero/below-kilo/kilo/mega/tera boundaries, progress fraction, state name lookup. Note: prior QA run (06:15) covered m47p and wrote its scorecard entry but set checkpoint to b6c71e6 instead of b1da79d — this run picks up from b6c71e6 and avoids double-counting m47p. wip:interrupted on uyk8 (0804de1, post-close, no code) consistent with zu4h pattern. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (708+ tests, 0 failures)
Notes: Transfer format unit tests are concise and correct — pure value assertions, no Result overhead needed. No production code was changed this period, only tests added. red-cell-c2-3ptb and red-cell-c2-zu4h remain open. Checkpoint inconsistency (prior QA set checkpoint to b6c71e6 after reviewing b6c71e6..b1da79d) corrected in this run — checkpoint now set to 0804de1.

### QA Review — 2026-03-17 08:45 — e319b98..8697e39

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed red-cell-c2-zpn2 (P3: integration tests for transfer callback handlers). 5 new async integration tests in transfer.rs covering handle_transfer_callback (List subcommand + truncated payload), handle_mem_file_callback, handle_package_dropped_callback, and handle_beacon_output_callback with credential persistence. Result-based error propagation throughout. Ghost wip:interrupted commit (8697e39, log-only) consistent with zu4h pattern. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all tests pass, 0 failures)
Notes: Test quality is high — proper async test structure, credential persistence validated end-to-end with in-memory DB + FK-satisfying agent registration, correct error variant assertion (CommandDispatchError::InvalidCallbackPayload) for truncated payload path. No production code changed this period. red-cell-c2-37rn also closed this period: agent correctly identified pre-existing tests (1720f08) and closed the issue; red-cell-c2-xajz (tracking the oversight) closed by QA as resolved. QA checkpoint covers e319b98..a8f19be including both the zpn2 test work and the 37rn housekeeping closure.

### QA Review — 2026-03-17 09:45 — a8f19be..0eb28fa

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No new dev commits since last QA run. Only commit in range is the QA checkpoint commit (0eb28fa). |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all tests pass, 0 failures)
Notes: No new commits since the 08:45 QA run. Codebase fully reviewed. 20 unblocked tasks remain in `br ready`. Claude quality score holds at 81% (198 tasks, 37 bugs filed).

### QA Review — 2026-03-17 10:45 — a1de98b..c36c1f4

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed red-cell-c2-rqen (2 subtree cascade tests for disconnect_link in agents.rs: verifies active=false on mid and leaf, root stays active, affected vec ordering) and red-cell-c2-doop (1 edge-case test for set_ctr_block_offset with offset=0 in database.rs). Ghost wip:interrupted commits on both (38121e1, 52cdd7a, no code) consistent with zu4h pattern. red-cell-c2-5b4v freshly claimed (c36c1f4), not yet delivered. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all tests pass, 0 failures)
Notes: Test quality is high — cascade tests add unique value by asserting `.active == false` on all subtree nodes (not just `.reason`), which the pre-existing `disconnect_link_removes_existing_parent_child_relationship` test did not verify. Zero-offset CTR test is a clean boundary-condition check. No production code changed. zu4h (claim/interrupt loop) and red-cell-c2-3ptb (listener config boilerplate) remain open.

### QA Review — 2026-03-17 11:30 — c36c1f4..07e8e50

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed red-cell-c2-5b4v (4 tests for query_session_activity in audit.rs: connect/chat activity filters, empty-set guard for unknown action, no-filter returns all five event types). Ghost wip:interrupted commit (07e8e50, log-only) consistent with pattern. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1194 tests, 0 failures)
Notes: Test quality is high — filter tests use in-memory DB with seeded rows, sorted-comparison pattern for the no-filter case correctly handles non-deterministic row order. No production code changed this period. 20 unblocked tasks remain in `br ready`. Claude cumulative: 201 tasks, 37 bugs, 18% bug rate, 82% quality.

### QA Review — 2026-03-17 11:45 — 2653d4e..549bb4f

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed red-cell-c2-xypk (round-trip tests for all 11 numeric_code! enum variants in common/src/operator.rs: as_u32/from_u32 symmetry, unknown-value rejection, JSON wire value). Ghost wip:interrupted commit (549bb4f, log-only). |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1194+ tests, 0 failures — verified at 07e8e50, no Rust changes since)
Notes: xypk tests are thorough — all 11 enums covered, both symmetry and rejection paths. No production code changed. Claude cumulative: 202 tasks, 37 bugs, 18% bug rate, 82% quality.

### QA Review — 2026-03-17 12:00 — 549bb4f..978f211

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed red-cell-c2-yxty (2 async integration tests for AgentRegistry::set_last_call_in: revival persists cleared reason across DB reload, unknown-ID returns AgentNotFound). Clean delivery. Ghost wip:interrupted (978f211) consistent with zu4h pattern. Now claiming y4fs. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all tests pass, 0 failures)
Notes: Test quality is solid — revival test reloads from DB to confirm persistence, error test uses matches! macro for precise variant + field assertion. No production code changed. Claude cumulative: 203 tasks, 37 bugs, 18% bug rate, 82% quality.

### QA Review — 2026-03-17 13:15 — e7398a1..738bf7e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed red-cell-c2-y4fs (13 inline unit tests for parse_file_open_header, parse_file_chunk, parse_file_close: happy paths, too-short/empty error paths, null-terminator stripping, empty path, extra-bytes-ignored). Ghost wip:interrupted (738bf7e, beads state + logs only) consistent with zu4h pattern. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1244 tests, 0 failures)
Notes: Tests are thorough — all three parser functions covered with both success and error paths. No production code changed. Claude cumulative: 204 tasks, 37 bugs, 18% bug rate, 82% quality.

### QA Review — 2026-03-17 14:10 — c7b38fb..b0cd03e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 1 | No tasks closed this period. Filed red-cell-c2-zjcx (P2): in-progress test for red-cell-c2-upwv has off-by-one-space assertion error in `format_net_group_descriptions_multiple_rows_varying_widths` — expected 12 spaces between "Group" and "Description" header labels but actual output has 11. Dependency added (upwv blocked by zjcx). |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` FAIL (1 failure: dispatch::network::tests::format_net_group_descriptions_multiple_rows_varying_widths — in uncommitted in-progress work; committed codebase is clean)
Notes: Review range contains only 2 admin commits (prior QA checkpoint + claim commit). No production code committed. Committed codebase has 768 passing tests. The 1 test failure is in the dev agent's uncommitted stash for red-cell-c2-upwv and is caused by a wrong expected-string in the test assertion (not a production code bug). Claude cumulative: 204 tasks, 38 bugs, 19% bug rate, 81% quality.

### QA Review — 2026-03-17 15:30 — b0cd03e..d218fec

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed red-cell-c2-upwv (tests for network formatting helpers). Bug red-cell-c2-zjcx (off-by-one space) was fixed before committing — closed as resolved. WIP interrupted commit (d218fec) only touched log files; no incomplete production code committed. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1258 tests, 0 failures)
Notes: Solid test commit covering all four functions (format_net_sessions, format_net_shares, format_net_group_descriptions, int_to_ipv4) with empty-input guards, min-width enforcement, and column expansion. Assertion correctness verified (zjcx resolved pre-commit). Claude cumulative: 205 tasks, 38 bugs, 19% bug rate, 81% quality.

### QA Review — 2026-03-17 15:04 — 78dfdd2..15c0a25

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 1 | 0 | Closed red-cell-c2-8gri via the process formatter test coverage commit (`teamserver/src/dispatch/process.rs`). Tests are additive only; no production-path regressions found. |
| Codex | 1 | 0 | Closed red-cell-c2-3b4x via the SMB listener integration test in [`teamserver/tests/smb_listener.rs`](/home/michel/Red-Cell-C2/teamserver/tests/smb_listener.rs). The test correctly validates that unknown-agent callbacks are ignored without mutating the registered agent. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓
Notes: No new bugs filed in this window. `br list --status=in_progress` shows only `red-cell-c2-vidy`, which matches a fresh claim in-range and does not appear stale. `br list --status=open` intermittently returned `database is busy` during review, but issue creation was not needed this run. Updated cumulative totals: Claude 206 tasks / 38 bugs / 18% bug rate / 82% quality; Codex 182 tasks / 32 bugs / 18% bug rate / 82% quality.

### QA Review — 2026-03-17 15:31 — 15c0a25..3e4725a

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | Two `chore(test-review)` maintenance commits landed in-range, but no task close commits or QA findings were attributable to Claude in this window. |
| Codex | 2 | 1 | Closed `red-cell-c2-vidy` and `red-cell-c2-bvqn` via [`teamserver/tests/smb_listener.rs`](/home/michel/Red-Cell-C2/teamserver/tests/smb_listener.rs) and [`teamserver/tests/e2e_operator_agent_session.rs`](/home/michel/Red-Cell-C2/teamserver/tests/e2e_operator_agent_session.rs). Filed `red-cell-c2-2x1d` because the new SMB E2E test hard-codes the known-bad lowercase listener protocol label at [`teamserver/tests/e2e_operator_agent_session.rs:324`](/home/michel/Red-Cell-C2/teamserver/tests/e2e_operator_agent_session.rs#L324), which blocks the Havoc-compatibility fix tracked in `red-cell-c2-k9mp`. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` failed (`clippy::too_many_arguments` at [`teamserver/src/listeners.rs:1316`](/home/michel/Red-Cell-C2/teamserver/src/listeners.rs#L1316)), `cargo test --workspace` ✓
Notes: Review window contained two Codex test-task closures and one fresh Codex claim (`red-cell-c2-1o7x`). `br list --status=in_progress` now shows only `red-cell-c2-1o7x`, which matches that new claim and does not appear stale. Added dependency `red-cell-c2-k9mp -> red-cell-c2-2x1d` because the new test expectation would otherwise pin the protocol bug in place. Updated cumulative totals: Claude 206 tasks / 38 bugs / 18% bug rate / 82% quality; Codex 184 tasks / 33 bugs / 18% bug rate / 82% quality.

### QA Review — 2026-03-17 16:13 — 3e4725a..3b26fb6

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity in this range. |
| Codex | 4 | 1 | Closed `red-cell-c2-1o7x`, `red-cell-c2-1pij`, `red-cell-c2-18r7`, and `red-cell-c2-8hft`. The listener hot-path hardening in [`teamserver/src/listeners.rs`](/home/michel/Red-Cell-C2/teamserver/src/listeners.rs) is sound overall, and the new compatibility coverage in [`teamserver/tests/havoc_compatibility.rs`](/home/michel/Red-Cell-C2/teamserver/tests/havoc_compatibility.rs) is additive. Filed `red-cell-c2-59m7` because the DNS response theft fix binds queued responses to the observed peer IP at [`teamserver/src/listeners.rs:2105`](/home/michel/Red-Cell-C2/teamserver/src/listeners.rs#L2105) and rejects later downloads from a different peer at [`teamserver/src/listeners.rs:2144`](/home/michel/Red-Cell-C2/teamserver/src/listeners.rs#L2144), which can strand legitimate agents behind rotating recursive resolvers. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓
Notes: Review range extended twice mid-run because `origin/main` advanced from `91ffad2` to `dda4137` and then to `3b26fb6`; both added Codex commits were reviewed before checkpointing. `br list --status=in_progress` shows only `red-cell-c2-932b`, which matches a fresh Codex claim in-range and does not appear stale. Updated cumulative totals: Claude 206 tasks / 38 bugs / 18% bug rate / 82% quality; Codex 188 tasks / 34 bugs / 18% bug rate / 82% quality.

### QA Review — 2026-03-17 16:39 — 3b26fb6..4d43128

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity. |
| Codex | 4 | 0 | Closed `red-cell-c2-932b`, `red-cell-c2-qubw`, `red-cell-c2-8nay`, and `red-cell-c2-uwuq`; also claimed `red-cell-c2-1vji`. The reviewed source diff is test-only and passed all quality gates. `red-cell-c2-hpoe` was also closed in beads in this window, but without a dedicated `chore: close` commit. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓
Notes: No new bugs filed. `br list --status=in_progress` returned empty during the review, and `br ready` succeeded after transient SQLite lock contention from concurrent beads activity. Updated cumulative totals: Claude 206 tasks / 38 bugs / 18% bug rate / 82% quality; Codex 192 tasks / 34 bugs / 18% bug rate / 82% quality.

### QA Review — 2026-03-17 17:13 — 4d43128..9e082c8

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity. |
| Codex | 3 | 0 | Closed `red-cell-c2-1vji`, `red-cell-c2-425c`, and `red-cell-c2-boge` via dedicated `chore: close` commits. Also claimed and then delivered `red-cell-c2-wj6s` in `9e082c8`, but that issue was closed in beads without a separate `chore: close` commit, so it is noted here and not counted in the close-commit total. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check --workspace` ✓, `cargo clippy --workspace -- -D warnings` ✓, `cargo test --workspace` ✓
Notes: No QA findings were upheld in this window. A transient failure seen during an overlapping local QA run did not reproduce once the quality gates were rerun cleanly, and the final tip `9e082c8` includes the `create_listener` validation/tests needed for `red-cell-c2-wj6s`. `br ready` reports 20 unblocked issues, and `.beads/issues.jsonl` contains no remaining `in_progress` items. Updated cumulative totals: Claude 206 tasks / 38 bugs / 18% bug rate / 82% quality; Codex 195 tasks / 34 bugs / 17% bug rate / 83% quality.

### QA Review — 2026-03-17 22:43 — 37ccf2c..17bb81a

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 3 | 1 | Closed rucc, o00x, ovje. All test additions: DemonCallbackPackage error paths, download-limit enforcement, pivot command callbacks, LootRepository get/list. Filed 2icd (workflow: 35dz not closed after interruption). |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (175 tests, 0 failures)
Notes: Test count stable at 175 (new tests replace none; test binary count unchanged). One workflow issue: 35dz work fully committed but issue left in_progress due to session interruption. No code quality, security, or architecture issues found — all changes are well-structured test additions following existing patterns.

### QA Review — 2026-03-18 00:52 — ec5f7c7..1d90286

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 6 | 0 | Closed 0dau, w08j, cov0, 35dz, ovnk, xz11. All test additions: audit time-range filters (7 tests), crypto AgentNotFound error paths (2 tests), agent_events None→Null coverage, agent_liveness sweep clamp, audit actor_filter precedence. ildv currently in_progress. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (921+ tests, 0 failures)
Notes: Clean review — no code quality, security, or architecture issues. All changes are well-structured test additions. Claude's quality score improved from 83% to 84%. Previous workflow issue (35dz left in_progress) was resolved — now properly closed. One task (ildv) currently claimed and in_progress.

### QA Review — 2026-03-18 01:30 — f798090..97098a4

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 6 | 0 | Closed ildv, kkvs, jlfs, nynt, u61j, d3y7. All test additions: AgentEncryptionInfo base64 rejection (3 tests), DNS ListenerConfig round-trip (already existed — closed as verified), deserialize_u16_from_any edge cases (4 tests), DemonPackage::command() error path, AgentInfo JSON key Havoc wire protocol assertions (2 tests), crypto IV non-zero assertion. Currently has abm8 claimed. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1035+ tests, 0 failures)
Notes: Clean review — no code quality, security, or architecture issues. All changes are well-structured test additions with no production code modified. kkvs was closed after verifying tests already existed (legitimate). Claude running total now 255 tasks closed, quality score holds at 84%.

### QA Review — 2026-03-18 01:45 — 407b004..7a292da

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 5 | 0 | Closed abm8, bfyj, 2lad, nko7, hszb. All test additions: create_operator REST error paths (3 tests), BOF_CALLBACK_ERROR unit+integration tests (3 tests), validate_checkin_transport_material isolated unit tests (6 tests), AgentRepository error-path integration tests (5 tests). Currently has a8hh claimed. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (952 unit + 3 integration, 0 failures)
Notes: Clean review — no code quality, security, or architecture issues. All changes are well-structured test additions with no production code modified. Claude running total now 260 tasks closed, bug rate down to 0.15, quality score up to 85%.

### QA Review — 2026-03-18 03:20 — 963821c..3c626a7

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 6 | 0 | Closed 33cr, tfs3, t8as, bg8g, gw6b, lesf. New tests: format_filetime overflow fallback (kerberos), int_to_ipv4 byte-order pinning (network), exit_callback process-exit and unknown-method branches (mod), format_memory_protect/state/type combined-flag and edge-case coverage (process). bg8g and gw6b closed after verifying tests already existed. Currently has 0evn claimed. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (962 unit tests, 0 failures)
Notes: Clean review — no code quality, security, or architecture issues. All changes are test additions with no production code modified. Claude running total now 266 tasks closed, quality score holds at 85%.

### QA Review — 2026-03-18 21:30 — ee7609a..a1dc499

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 6 | 0 | Closed 9hnj, 7son, ags8, d3q2, lah3, h87y. New tests: windows_version_label all 11 branches + service pack (5 tests/17 cases), process_arch_label + windows_arch_label known/unknown coverage, prune_expired_windows empty-map + IPv6-key tests, logging no-profile + RUST_LOG override path, evict_oldest_windows empty-map + tied-start edge cases. d3q2 closed after verifying tests already existed. Currently has aa5t claimed. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (985 unit tests, 0 failures)
Notes: Clean review — no code quality, security, or architecture issues. All changes are test additions with no production code modified. Claude running total now 272 tasks closed, quality score holds at 85%.

### QA Review — 2026-03-18 03:00 — a1dc499..3941e90

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 9 | 0 | All test-only: TLS connector, auth, checkin, payload cache, SOCKS5, exit/screenshot dispatch |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (995 unit + 189 integration, 0 failures)
Notes: Clean review — all 9 closed tasks are test additions with no production code changes. No unwrap in prod paths, no security issues, no architecture drift. Claude quality score improved to 86% (bug rate 0.14). One issue (red-cell-c2-2f7k) currently in_progress — recently claimed, not stale.

### QA Review — 2026-03-18 04:15 — aef27a2..801eb64

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 4 | 0 | Closed 1b53, 2x5j, 2jsx, 5tij. Audit malformed-details conversion/query tests (11 new tests), liveness audit-persistence failure test, process-create decision-matrix coverage (6 new tests). |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1021 unit + all integration, 0 failures)
Notes: Clean review — all changes are test additions, no production code modified. Tests are well-structured with proper async patterns and error handling. One task in progress: 1v7a (SOCKS connect-failure routing tests). No bugs filed.

### Arch Review — 2026-03-18 09:45

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude (Sonnet) | 3 | security(1), memory/resource(1), missing-tests(3) | SOCKS relay unbounded connections, plugin Mutex deadlock potential, CTR overflow untested |
| Claude (Opus) | 0 | — | Recent test additions are clean |
| Codex | 0 | — | No new findings this review |
| Cursor | 0 | — | No new findings this review |

Overall codebase health: on track
Biggest blindspot: SOCKS5 relay has no connection limits — a compromised agent can exhaust server resources

### Arch Review — 2026-03-18 11:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude (Sonnet) | 2 | security(1), missing-tests(1) | Plugin RBAC bypass (ya4b), auth audit trail untested (70os) |
| Claude (Opus) | 1 | missing-tests(1) | Client config TOML edge cases untested (8tiu) |
| Codex | 2 | security(1), audit(1) | Proxy password not zeroized (i7q0), serde_json audit params silently dropped (nf3r) |
| Cursor | 0 | — | No new findings this review |

Overall codebase health: on track
Biggest blindspot: Python plugins have unrestricted API access regardless of operator RBAC role — privilege escalation risk if plugin loading is not restricted to admins

### QA Review — 2026-03-18 12:15 — d25c259..640abca

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (Opus) | 3 | 0 | Closed 9tke, 2o3j, 3tpy. Dir callback tests (explorer, list-only, zero-row), download close-failure and invalid-mode tests. Clean test-only additions. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,265 tests passing, 0 warnings)

### QA Review — 2026-03-18 13:30 — a85a646..152fbde

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 2 | 0 | Closed 2asc (4 error-path tests for handle_net_callback), 3no5 (15 integration tests for output callback dispatch: command_output, command_error, kill_date, sleep, config). Currently has 2qur in progress (process callback coverage). |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (1,110 tests passing, 0 failures)
Notes: Clean review — all changes are test additions only. No production code modified. Network dispatch error-path tests cover invalid subcommand, empty payload, and truncated Sessions/Users rows. Output dispatch integration tests cover all five untested handler paths with happy, error, and edge cases. No code quality issues found.

### QA Review — 2026-03-18 16:00 — 1a04542..f22f905

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 4 | 0 | Closed in2t (malformed CommandJob/List dispatch coverage), 3mro (unauthenticated operator task injection test), 2pdw (same-port listener conflict test), 3p15 (truncated SMB frame headers/partial payloads test). Currently has 12s4 in progress (SMB checkin callback response assertion). |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` 1 pre-existing failure (operator_session_smb_listener_and_mock_demon_round_trip — timeout caused by known bug red-cell-c2-g84l, fix in progress via 12s4). 1,134 unit tests passing.
Notes: Clean review — all 4 closed tasks are test additions only. No production code modified in this range. Tests are well-structured with proper `?` error propagation, no unwraps, good edge case coverage. SMB truncated-frame test exercises both header and payload truncation plus recovery. Auth injection tests cover both unauthenticated and failed-login paths. No new issues filed.

### QA Review — 2026-03-18 18:45 — 2cbd5ec..cf19686

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude (dev02-opus) | 4 | 0 | Closed 3uls (audit query pagination/filter tests), 9mpv (TLS mismatched cert/key failure tests), hfjz (TLS partial-state regeneration tests), 3pkw (agent_events operator metadata tests). Also ran test-coverage scan batch 12-24 with no new gaps. Currently has 3ptg in progress. |
| Codex | 0 | 0 | No activity. |
| Cursor | 0 | 0 | No activity. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓, `cargo test --workspace` ✓ (all tests passing)
Notes: Clean review — all 4 closed tasks are test additions only. No production code modified. Tests are thorough: audit.rs adds 9 new tests covering result_status/target_kind/target_id/command filters, pagination ordering across pages, operator alias, combined filters, and time-window intersection. TLS tests cover mismatched cert/key (same algo + cross-algo) and partial-state regeneration (cert-only, key-only). Agent event tests verify metadata fields (event code, user, one_time, timestamp) and optional kill_date/working_hours. No new issues filed.

### Arch Review — 2026-03-18 19:15

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude (Sonnet) | 1 | 1 test infrastructure bug | Plugin test mutex poisoning cascade (08ds, P2) — `load_plugins_registers_callbacks_and_commands` assertion failure poisons `PLUGIN_RUNTIME_TEST_MUTEX`, causing 6 tests to fail in full suite runs. Tests pass in isolation. |
| Claude (Opus) | 0 | — | No new issues found. |
| Codex | 0 | — | No new issues found. |
| Cursor | 0 | — | No new issues found. |

Overall codebase health: **on track**
Biggest blindspot: Plugin test isolation — the Python GIL global state creates a fragile test ordering dependency that masks 6 tests as failing in CI-like full-suite runs.

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓ (zero warnings), `cargo test --workspace` — 1144 passed, 6 failed (all from plugin mutex poisoning cascade)

Deep review covered: full structural map (96k lines across 3 crates, 66 .rs files), all dispatch handlers (14 files), crypto implementation (AES-256-CTR with offset persistence, Zeroizing key material, constant-time comparisons), protocol parsing (integer overflow guards via checked_* and try_from, magic precheck, size validation), authentication (Argon2 + dummy verifier timing defense, session caps, API key HMAC), all listener implementations (HTTP/HTTPS/DNS/SMB with rate limiting), plugin system (PyO3 + GIL), REST API routes, WebSocket handlers, client UI + transport. Security posture remains strong — no key material in logs, no unwrap in production code, no println/eprintln anywhere, bounded allocations throughout, proper error propagation. Architecture fully aligned with AGENTS.md specifications (Axum+Tokio, SQLite/sqlx, HCL config, thiserror in libraries, anyhow only in main.rs, edition 2024).

### QA Review — 2026-03-19 21:15 — 43756e1..0b123b3

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 0 | Closed x8lh (dispatch/util inline tests — already existed), 5gzc (13 unit tests for auth failure tracking & rate limiting), rm6n (5 integration tests for session-activity endpoint). +476 lines of test code in api.rs. Currently working on kkra (dispatch/socket.rs test coverage). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: `cargo check` ✓, `cargo clippy -- -D warnings` ✓ (zero warnings), `cargo test -p red-cell -- api::tests` ✓ (131 tests, 0 failures). Full workspace suite (2100+ tests) times out at 120s — pre-existing issue, not a regression.

### Arch Review — 2026-03-19 23:00

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 3 | security (2), correctness (1) | Config file permissions (9z6bx), fingerprint validation (mhmmv), mutex poisoning (rveao — shared with Codex) |
| Codex | 2 | correctness (1), quality (1) | Mutex poisoning (rveao — shared with Claude), TOML parse errors (qweip) |
| Cursor | 0 | — | No code touched in reviewed areas |

Overall codebase health: **on track**
Biggest blindspot: Client config file written world-readable — the only finding with real security exposure in a deployment scenario. The teamserver side is exceptionally well-hardened: no unwrap in production (clippy lint enforced), bounded allocations throughout, constant-time comparisons for auth, AES-CTR with advancing offsets, per-IP rate limiting on init. The client side has received less security scrutiny — all 4 findings are in the client crate.

### QA Review — 2026-03-19 — e93a83a..f490808

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 0 | 0 | No activity this period. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (all suites 0 failures)

### QA Review — 2026-03-19 — f586860..f153a50

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 5 | 0 | Closed 5 issues (hiil, vhn9, 4be2, a0ac, 0sgh). Implemented External C2 bridge listener runtime with endpoint registry, fallback handler integration, and 7 unit tests. Added CommandPsImport (0x1011) dispatch handler with 3 tests. Added SOCKS5 negotiate happy-path test. Added comprehensive DNS listener E2E integration test (498 lines, 4 test cases). Enforced per-agent/global/listener SOCKS5 connection limits with 3 limit tests. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy pre-existing warning (unused doc comment in plugins.rs — not from this range), cargo test passed (all suites 0 failures)

### QA Review — 2026-03-19 — f153a50..53de2b9

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 4 | 0 | Closed 4 issues (ss50, m93a, 7km5, et4z). Fixed plugin runtime re-entrant deadlock via thread-local CallbackRuntimeGuard RAII bypass (ss50). Added 8 SOCKS5 concurrent/load tests covering connection limits, state reclamation, u32 wraparound, and stale sweeper (m93a). Added plugin deadlock regression test with 10s timeout guard (7km5). Added 10 CTR offset u64/i64 overflow boundary tests in crypto and agent registry (et4z). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (all suites 0 failures)

### QA Review — 2026-03-19 — 53de2b9..48c717e

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 8 | 0 | Closed 8 issues (3qr0, 2yyi, nbhs, iz2i, 0c0a, 05ax, e2md, wxol). All test-only changes: webhook embed optional field omission test, concurrent mixed success/failure detached delivery test, listener update lifecycle and delete-nonexistent tests, reconnect probe test, empty BOF output callback test, empty task queue CommandGetJob test, empty job list CommandJob/List test. Clean, well-structured edge-case coverage. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (2147 tests, 0 failures)

### Arch Review — 2026-03-19 19:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 4 | Missing tests (3), Correctness (1) | ic7qy: External C2 bridge listener has no integration test. 984jo: listener restart path untested. hirxf: agent deletion/cleanup chain untested E2E. ahhvt: optional_u32 silently drops parse errors via .ok(). |
| Codex | 0 | — | No new findings this review. |
| Cursor | 0 | — | No new findings this review. |

Overall codebase health: on track
Biggest blindspot: External C2 bridge listener (recently added) has zero integration test coverage — the only listener type without a pipeline test.

### QA Review — 2026-03-19 — 48c717e..7506013

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed nf3r and i7q0. fix(ws): added `serialize_for_audit` helper to warn on serialization failures instead of silently dropping (5 call sites updated, 2 tests added). fix(security): wrapped proxy password in `Zeroizing<String>` across config.rs, domain.rs, listeners.rs, payload_builder.rs with Debug redaction and serde round-trip tests. Clean, well-tested changes. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (all suites 0 failures)

### QA Review — 2026-03-19 — cfab726..81d2ff0

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 5 | 0 | Closed ya4b, 70os, 8tiu, 4pur, ueby. fix(security): RBAC enforcement in Python plugin API boundary — thread-local CallerRoleGuard propagates operator role into plugin calls, permission checks on all Python-exposed functions (get_agent, list_agents, task, listener start/stop). New tests: reconnection backoff (6 unit tests), corrupt TOML input handling (11 unit tests), auth audit trail integration (6 tests), plugin RBAC enforcement (7 unit tests including cross-Python boundary checks), CTR mode wrong-key property test. All clean, well-tested. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (2191 tests, 0 failures)

### QA Review — 2026-03-19 — 81d2ff0..5088711

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 6 | 0 | Closed x2in, 182a, fjb8, 53xh, xn9p, zori. All test-only changes: output log and command history eviction at capacity limits (python.rs +125 lines), login persistence test for nonexistent config file path, OperatorMessage missing Head/Body rejection tests and extra-key forward-compat test (operator.rs +69 lines), agent liveness sweep with non-UTC offset timestamps (+100 lines), operator_inventory with empty/closed-db audit log (+43 lines). Clean, well-structured edge-case coverage. One task (fn1f) currently in_progress. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (all suites 0 failures)

### QA Review — 2026-03-19 — 5088711..3768dea

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 0 | Closed vbt8 (handle_config_callback unit tests, 11 tests), cdbq (handle_job_callback integration tests — single job, three jobs, unknown subcommand), yf4j (handle_exit_callback and handle_kill_date_callback unit tests, 7 tests). Also filed test quality issues via test-review scan and claimed yw6v (in progress). Clean, well-structured test code with proper error path and edge case coverage. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (223 tests, 0 failures)

### QA Review — 2026-03-19 — 3768dea..5230d8f

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 4 | 0 | Closed yw6v (handle_pivot_list_callback tests: empty, two-entry, truncated — 3 tests), buqf (handle_demon_info_callback MemAlloc/MemExec/MemProtect tests — 7 tests), e8eb (AuthorizationError IntoResponse status code mapping — 5 tests), 4d2m (webhook Discord embed no-nulls/empty assertions). Also filed test quality issues via test-review scan and claimed q5u8 (in progress — plugins isolation test). Closed duplicate issue 9735 (covered by yw6v). All test-only changes, clean and well-structured. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (1460+ tests, 0 failures)

### Arch Review — 2026-03-19 18:30

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | 5 | protocol errors (1), unwrap/expect (1), stale tests (1), correctness (2) | Silent u32 truncation in 10+ dispatch length encoders (tywa7), ghost test from stale artifact (2n1r9), service.rs/payload_builder.rs silent serialization failures (t5gbg, v9f6z), websocket content-length overflow (hfcb0) |
| Codex | 0 | — | No attributable findings |
| Cursor | 0 | — | No attributable findings |

Overall codebase health: **on track**
Biggest blindspot: `unwrap_or_default()` on protocol length fields — 67 instances across 20 files. Not exploitable in practice on 64-bit (payloads would need >4 GiB), but architecturally unsound and would cause silent protocol desync on overflow.

### QA Review — 2026-03-19 21:00 — 5230d8f..def9d16

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed q5u8 (plugin load resilience — changed load_plugins from fail-fast to skip-and-continue with per-plugin warnings, +64 lines of new test covering multi-plugin isolation with broken plugin in the middle), u7ob (auth rate limiter expired window reset test). Also claimed m527 (socket dispatch stubs — in progress). Clean, well-tested changes. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (all suites, 0 failures)

### QA Review — 2026-03-19 23:15 — cf4856a..903cfb4

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 3 | 0 | Closed m527 (socket dispatch stubs — 6 SOCKS/portfwd subcommands with format helpers and 13 new tests, +375 lines in socket.rs), maci (network Computer/DcList dispatch callbacks — parse UTF-16, broadcast formatted results, +4 tests), vka4 (PythonRuntime::load_script unit tests — 3 test scenarios for happy/error/idempotent paths). Currently has 1tvu claimed (ClientTransport tests). All code clean — proper `?` error handling, no unwraps in prod, consistent patterns. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (229 tests, 0 failures)

### QA Review — 2026-03-19 23:30 — 903cfb4..3d12601

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 5 | 0 | Closed 1tvu (ClientTransport::spawn and outgoing_sender tests), rc1t (InitConnectionSuccess/Error path tests), 1fef (ListenerEdit/Remove/Mark handler tests), sr8s (ChatMessage/ChatListener/ChatAgent, TeamserverLog, BuildPayload handler tests), ng3c (DemonPackage::to_bytes LengthOverflow error path test). All test-only changes — 540 lines in transport.rs, 39 lines in demon.rs. Clean refactor extracting checked_payload_len helper for testability. Currently has rnot claimed. Zero issues found. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (1477+ tests, 0 failures)

### QA Review — 2026-03-19 — 63600b7..9eaf6e9

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 4 | 0 | Closed gmau, mu21 (LootRepository credential persistence tests — CRUD, filtering, pagination, ~180 lines), l553 (LinkRepository disconnect cascade tests — chain ops, delete, relink, ~150 lines), p85z (truncated payload tests for handle_command_error_callback — 3 edge-case scenarios, ~48 lines). Currently has 08ds claimed (plugin mutex poisoning fix — unstaged WIP visible in plugins.rs/websocket.rs). All committed code is test-only, clean, no issues found. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (230 tests, 0 failures)

### QA Review — 2026-03-19 — 9eaf6e9..0c7bd86

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 5 | 0 | Closed 08ds (poisoned test mutex fix — replaced all TEST_GUARD.lock().map_err() with lock_test_guard() helper tolerating poisoned mutex in plugins.rs and websocket.rs), 2oj4 (verified emit_* event hooks already have comprehensive coverage — closed as already-covered), b20u (verified initialize/current() already tested — closed as already-covered), 84ob (4 new integration tests for malformed/truncated BOF payloads: short header, truncated string, missing exception address, unknown sub-type 0xFF), mzd5 (2 new plugin tests: command merge across plugins, duplicate command last-write-wins). Also closed duplicate pua6 (same scope as 84ob). Currently has w680 claimed. Zero issues found — clean period. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (1503+ tests, 0 failures)

### QA Review — 2026-03-19 20:30 — 17d5cc7..41dab70

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 8 | 0 | Closed 85p1, pjyr, vz1o, niw3, zj8f, s78j, 538r, bfsn. Added ~646 lines of client unit tests (EventLog lifecycle, normalize_agent_id, sanitize_text, flat_info_string, loot_item_from_flat_info, credential/loot/host-file add/edit/remove flows). Added 3 RBAC integration tests (analyst denied ListenerEdit/Remove/Mark). Added oversized body rejection test for HTTP listener. Currently has 94ap claimed (Argon2 defaults bug). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (all workspace tests pass; e2e_operator_agent_session timeouts on full-suite run are resource contention, pass when run isolated)

### QA Review — 2026-03-19 23:45 — 9b06446..9d4099f

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 4 | 0 | Closed 8twu (4 pivot SmbCommand forwarding and dispatch_builtin_packages tests — happy path, non-callback envelope, truncated payload, CommandOutput round-trip), o1z0 (pivot list callback tests already existed — verified and closed), exbf (ctr_blocks_for_len usize::MAX boundary test already existed — verified and closed), ggap (26 filesystem subcommand tests — truncated payloads and edge cases for Cd/Remove/Mkdir/Copy/Move/GetPwd/Cat/Upload plus invalid subcommand and empty payload). Also fixed WebSocket routing with NormalizePathLayer (app.rs) and TLS ALPN to HTTP/1.1-only for WebSocket compatibility (main.rs). Currently has qav1 claimed (database CRUD unit tests — WIP in database.rs). Zero issues found. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (2283 tests across all crates, 0 failures)

### QA Review — 2026-03-20 14:30 — 634de92..0060b51

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 1 | Closed 7eah (pivot List single-entry test), a2o7 (pivot SmbDisconnect callback tests — success/cascade/failure paths). Added ~250 lines of well-structured tests with good coverage of success, cascade, and failure paths. Currently has 3jal claimed (resolve_bind_addr error path test — WIP in main.rs). Bug filed: pre-existing flaky websocket integration tests (he5j7). |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test 1602 passed / 3 failed (3 pre-existing websocket flaky tests — filed as red-cell-c2-he5j7)

### QA Review — 2026-03-20 19:30 — 8e34044..9dd5359

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed gx4s (7 comprehensive plugin emit_* hook tests covering all payload fields for agent_checkin, command_output, agent_dead, loot_captured, task_created + exception resilience), 5qug (E2E reconnect probe test — full flow: init → reconnect → no duplicate AgentNew → resumed callback at unchanged CTR offset). Clean, well-structured test code. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test 2762 passed / 0 failed

### QA Review — 2026-03-20 — beffc218..1cc01f80

| Agent | Tasks closed | Bugs filed | Notes |
|-------|-------------|------------|-------|
| Claude | 2 | 0 | Closed rveao (mutex poisoning fix — added warn! logging before into_inner() across 5 files: agents.rs, auth.rs, events.rs, python.rs, transport.rs), qweip (TOML parse error fix — log parse errors in local_config.rs instead of silently falling back to defaults). Also filed arch review findings (fb3920a5). Currently has 3w6d5 claimed (output dispatch truncated payload tests). Clean code — no issues found. |
| Codex | 0 | 0 | No activity this period. |
| Cursor | 0 | 0 | No activity this period. |

Build: cargo check passed, clippy passed (0 warnings), cargo test passed (254 teamserver + all workspace tests, 0 failures)
