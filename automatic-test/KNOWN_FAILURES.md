# Autotest known-failure shortcuts

Diagnostic patterns observed in past `--loop autotest` runs.  Match each new
scenario failure against this table **before** investigating from scratch.

## How the autotest agent uses this file

1. Read the whole file at Step 1 (Orient) so the patterns are in working memory.
2. During Step 5 (Classify), for each ✗ FAILED scenario:
   - Scan its error string + stderr against every row's *Signature*.
   - **Active match** — the bead is filed and (probably) being worked on.
     Reference the bead in your run report, bump *Last seen* to today,
     skip the investigation. **Do not file a duplicate.**
   - **Resolved match** — a prior fix should have addressed this. If the
     failure is still happening, the fix didn't stick. File a *new* bead
     describing the regression (do not reopen the resolved one) and add
     it to the *Active* section.
   - **No match** — investigate as usual, file a bead, then add a row to
     the *Active* section before you commit.
3. At Step 8 (Land the plane), prune *Resolved* rows whose `Resolved at`
   date is older than 14 days **and** were not seen this run.

Keep this file short — patterns should be specific enough that an agent
can match by `grep -F` from the scenario log, not generic enough to false-positive.

---

## Active

Failures whose bead is open or in-progress.  When the bead closes, move the
row to *Resolved* and add the closing commit / fix description.

| Signature (substring of error / stderr) | Scenario | Bead | First seen | Last seen | Status |
|----------------------------------------|----------|------|------------|-----------|--------|
| `[TIMEOUT] timeout: timed out waiting for output from task` | 04, 06, 07, 08, 11, 21 | red-cell-c2-1f7q1 | 2026-04-24 | 2026-05-02 | P1, Phantom crashes ~1s after first task dispatch; agent.dead event within 1s of task; all prior fixes (vk3xs etc.) are resolved — new crash site |
| `Path:[]` | 05, 14, 19 | red-cell-c2-2u0hw | 2026-04-30 | 2026-05-02 | P1, Demon Windows PATH still empty after qaru8 encode_utf16 fix — direct exes start (`Process started: Path:[]`) but cmd builtins (echo) still fail (`Process could not be started: Path:[]`), regression of red-cell-c2-qaru8 |
| `Timed out after 60s waiting for agent checkin` | 17 | red-cell-c2-vudj9 | 2026-04-29 | 2026-05-02 | P2, Archon Windows checkin still times out after S4U schtask fix — agent runs but makes zero TCP connections, regression of red-cell-c2-550gu |
| `No space left on device` | 22, 23 | red-cell-c2-sb5bm | 2026-05-02 | 2026-05-02 | P3, sccache grew to 8.3 GB filling root FS — environment issue, not product; workaround: rm -rf ~/.cache/sccache |

---

## Resolved

Failures whose bead has been closed or whose root cause was fixed inline.
Kept for ~14 days so a regression is detected as a fix-didn't-stick rather
than a new bug.

| Signature (substring of error / stderr) | Scenario | Bead | Resolved at | Notes |
|----------------------------------------|----------|------|-------------|-------|
| `Process could not be started: Path:[]` (qaru8 encode_utf16 fix) | 05, 14, 19 | red-cell-c2-qaru8 | 2026-05-01 | encode_utf16("") now emits length=0; CreateProcessW no longer fails for direct exes. PATH still empty → cmd builtins still fail. **REGRESSED** — see red-cell-c2-2u0hw. |
| `Timed out after 60s waiting for agent checkin` (S4U schtask fix) | 17 | red-cell-c2-jv15n, red-cell-c2-550gu | 2026-05-01 | jv15n bisected to "no TCP connection"; 550gu switched execute_background to S4U — agent now runs as user, not SYSTEM. Agent still makes zero TCP connections. **REGRESSED** — see red-cell-c2-vudj9. |
| `Timed out after 30s waiting for 10 new agent checkins` | 14 | red-cell-c2-8ss6q | 2026-04-30 | 10/10 Demon agents now check in (was 0/10). Checkin fixed by stale-process cleanup + listener-name filtering. Command execution now blocked by new PATH bug (red-cell-c2-z1hl9). |
| `Process could not be started: Path:[]` (CreateEnvironmentBlock fix) | 05, 14, 19 | red-cell-c2-z1hl9 | 2026-04-30 | Commits bfbf64fd/cbb0353d/481dd7be added CreateEnvironmentBlock. **REGRESSED** — fix ineffective, see red-cell-c2-qaru8. |
| `Timed out after 60s waiting for agent checkin` (X25519 fix attempt) | 17 | red-cell-c2-al4eo | 2026-04-30 | X25519.c fix was interrupted (WIP commits). **REGRESSED** — see red-cell-c2-jv15n. |
| `[TIMEOUT] timeout: timed out waiting for output from task` (seq_num desync fix) | 04, 06, 07, 11, 21 | red-cell-c2-5dggm | 2026-04-29 | ECDH seq_num desync: always increment callback_seq after send attempt. **REGRESSED** — see red-cell-c2-vk3xs |
| `[TIMEOUT] timeout: timed out waiting for output from task` (mprotect SIGSEGV fix) | 04, 06, 07, 08, 11, 19, 21 | red-cell-c2-vk3xs | 2026-04-28 | reqwest connection pool kept a background Tokio task that accessed heap during mprotect_sleep PROT_NONE window → SIGSEGV. Fixed with pool_max_idle_per_host(0) in Phantom transport. Commit 20f2d6d4. **REGRESSED** — still observed 2026-05-02, new bead red-cell-c2-1f7q1. |
| `WMI Win32_Process.Create failed: ReturnValue=21` | 05, 08, 14, 17, 19 | red-cell-c2-irxsr | 2026-04-29 | PureWindowsPath fix for WMI CurrentDirectory extraction. WMI deploys now work. Downstream issues exposed: sc17 Archon checkin (red-cell-c2-al4eo), sc14 stress checkin (red-cell-c2-8ss6q). |
| `GET_JOB accepted (HTTP 200): got HTTP 404` | 13 | red-cell-c2-irlsn | 2026-04-29 | Fixed GET_JOB heartbeat packet: removed spurious u32be(0) length prefix. sc13 passes. |
| `DoH uplink chunk 0/1 expected NXDOMAIN (rcode=3), got rcode=5` | 20 | red-cell-c2-qb8gw | 2026-04-29 | Fixed by commit 1de06fac (irlsn fix). sc20 now skips for DNS resolution issue, not REFUSED. |
| `[TIMEOUT] timeout: timed out waiting for output from task` (CommandProc persist fix) | 04, 05, 07, 19, 21, 23 | red-cell-c2-4vogq | 2026-04-28 | Persisted CommandProc/CommandProcList callbacks to ts_agent_responses, added request_id matching. **REGRESSED** — see red-cell-c2-5dggm → red-cell-c2-vk3xs |
| `CLI subprocess did not exit within expected timeout (40s)` (CLI hang variant) | 11 | red-cell-c2-4vogq | 2026-04-28 | Same family as above; CLI subprocess hang is cascade of task output pipeline failure. **REGRESSED** — see red-cell-c2-vk3xs |
| `Timed out after 30s waiting for remote upload /tmp/rc-test/uploaded-` | 06 | red-cell-c2-roz1h | 2026-04-28 | ECDH batch re-queue fix: upload now succeeds (SHA-256 verified in 2026-04-29 run). Download side still fails (cascade of task output). |
| `Timed out after 30s waiting for screenshot loot entry` | 08 | red-cell-c2-dn3yy | 2026-04-28 | Raised MAX_AGENT_MESSAGE_LEN to 100 MiB. **REGRESSED** — screenshot loot still times out, now cascade of task-output (red-cell-c2-vk3xs). |
| `Timed out after 30s waiting for 10 new agent checkins` (WMI validation) | 14 | red-cell-c2-4302s | 2026-04-28 | Added WMI ReturnValue validation. WMI now fixed (red-cell-c2-irxsr). **NEW ISSUE** — checkin itself fails under stress (red-cell-c2-8ss6q). |
| `Timed out after 60s waiting for agent checkin` (WMI validation) | 17 | red-cell-c2-4302s | 2026-04-28 | Same fix as above. **NEW ISSUE** — Archon checkin fails despite WMI fix (red-cell-c2-al4eo). |
| `last_seen never changed from initial '` | 24 | red-cell-c2-dz867 | 2026-04-28 | ECDH exit_requested set after successful batch send. **FIXED** — sc24 passes. |
| `[TIMEOUT] timed out waiting for output from task` (wstring fix) | 04, 11, 21 | red-cell-c2-2g1nj | 2026-04-27 | Phantom wstring null terminator fix. **REGRESSED** — see red-cell-c2-asy66 → 4vogq → 5dggm → vk3xs |
| `Timed out after 60s waiting for agent checkin` (Invoke-WmiMethod fix) | 14, 17, 19 | red-cell-c2-gxabx | 2026-04-27 | Switched to Invoke-WmiMethod for Windows deploy. **REGRESSED** — see red-cell-c2-db6yd → 4302s → irxsr |
| `still present in agent list after 120s — expected implant to stop after kill-date` | 22, 23 | red-cell-c2-dv5ev | 2026-04-27 | Phantom pre-init kill-date + working-hours checks. Scenarios 22/23/24 now pass. |
| `[TIMEOUT] timeout: timed out waiting for output from task` (wstring follow-up) | 04, 11, 21 | red-cell-c2-asy66 | 2026-04-27 | Phantom run loop retry/callback-send fix. **REGRESSED** — see red-cell-c2-4vogq → 5dggm → vk3xs |
| `Timed out after 60s waiting for agent checkin` (listener wiring follow-up) | 14, 17, 19 | red-cell-c2-db6yd | 2026-04-27 | Listener name wiring fix. **REGRESSED** — see red-cell-c2-4302s → irxsr |
| `Address already in use (os error 98)` on port 19181/19182 | 04, 06, 07, 11, 17, 21–24 | red-cell-c2-hyhgf | 2026-04-27 | Preflight listener cleanup. Not seen this run. |
| `unparseable last_seen` (nanosecond timestamp with Z suffix) | 24 | *(no bead — fixed inline)* | 2026-04-27 | parse_last_seen now strips Z suffix and truncates nanoseconds to microseconds |
| `cargo build --release --target x86_64-pc-windows-gnu` + `error[E0308]` in Specter | 05, 06, 07, 08 | red-cell-c2-z85a3 | 2026-04-27 | Specter cross-compile fixes landed; not seen since 2026-04-28. |
| `panic` + `TypeId` + `payload build-wait` clap collision | 03 | red-cell-c2-2edsr | 2026-04-26 | Renamed `BuildWait --output` → `--dst` to avoid TypeId collision with global `--output` (commit 71d115df) |
| Listener create fails: `address already in use` on 19081 / 19082 | 04, 05, 06, 07, 08, 11 | *(no bead — fixed inline)* | 2026-04-26 | `test.py` now stops + deletes leftover non-default listeners before scenarios start (commit 311d6253) |
| HTTP 429 / rate-limit cascade after scenarios 01–11 | 12–24 | *(no bead — fixed inline)* | 2026-04-26 | `profiles/autotest.yaotl` `RateLimitPerMinute` raised 120 → 600 (commit 311d6253) |
| `[INVALID_ARGS] unknown format 'elf': expected exe, dll, or bin` | 04, 06, 07, 11, 15, 21–24 | *(no bead — fixed inline)* | 2026-04-24 | Replaced `fmt='elf'` with `fmt='exe'` for Phantom (commit 9cddb9a5) |
| `not reachable via SSH` against the Windows VM despite `whoami` working | every scenario with `[windows]` | red-cell-c2-3jlpo | 2026-04-24 | `preflight_ssh` sent `true`, which `cmd.exe` does not know — switched to `exit 0` (commit c6fb4086) |
| `[TIMEOUT] timed out waiting for output from task` (original) | 04, 07, 11, 21 | red-cell-c2-yde2a | 2026-04-25 | CommandProc(0x1010) + DemonCallbackError::Generic fix. **REGRESSED** — see red-cell-c2-3ecje |
| `Timed out after 60s waiting for agent checkin` (original Windows Demon) | 05, 08, 14, 16, 17, 19 | red-cell-c2-2it9u | 2026-04-25 | HeapEnc packing fix for Demon transport config. **REGRESSED** — see red-cell-c2-jtsiv |
| `[TIMEOUT] timed out waiting for output from task` (seq_num fix) | 04, 11, 14 | red-cell-c2-3ecje | 2026-04-26 | ecdh_send_packages seq_num prefix fix. **REGRESSED** — see red-cell-c2-pa1wi |
| `Timed out after 60s waiting for agent checkin` (AllowLegacyCtr fix) | 16, 17, 19 | red-cell-c2-jtsiv | 2026-04-26 | AllowLegacyCtr + legacy_mode fix. **REGRESSED** — see red-cell-c2-dvd3p |
| `cargo build --release --target x86_64-pc-windows-gnu` + `error[E0433]` in `common/src/tls.rs` | 05, 06, 07, 08 | red-cell-c2-f33x9 | 2026-04-26 | Gated unix imports behind cfg(unix). **NEW ERROR** — see red-cell-c2-5k8ed |
| `agent ... still present / checked in / sleep_interval` (env var bake fix) | 22, 23, 24 | red-cell-c2-btwo0 | 2026-04-25 | rust_agent_env_vars baking fix. **REGRESSED** — see red-cell-c2-0h0et |
| `[TIMEOUT] timed out waiting for output from task` (batch callback fix) | 04, 11, 21 | red-cell-c2-pa1wi | 2026-04-27 | Batch all callbacks into single DemonMessage+session packet. **REGRESSED** — see red-cell-c2-2g1nj |
| `Timed out after 60s waiting for agent checkin` (callback_host normalization) | 14, 17, 19 | red-cell-c2-dvd3p | 2026-04-27 | Normalize callback_host, raise DEMON_INIT per-IP limit. **REGRESSED** — see red-cell-c2-gxabx |
| `error: extern blocks must be unsafe` in `agent/specter/src/token/enumerate_windows.rs` | 05, 06, 07, 08 | red-cell-c2-5k8ed | 2026-04-27 | Mark ntdll FFI block as unsafe extern for Rust 2024. **NEW ERROR** — see red-cell-c2-as0gd |
| `agent ... still present / checked in / sleep_interval` (env-var clearing fix) | 22, 23, 24 | red-cell-c2-0h0et | 2026-04-27 | Clear inherited PHANTOM_*/SPECTER_* from compiler env. **REGRESSED** — see red-cell-c2-dv5ev |
| `Python was not found` (DoH probe on Windows VM) | 20 | red-cell-c2-2gg26 | 2026-04-25 | preflight_dns uses PowerShell on Windows targets. Scenario 20 now skips due to DNS resolution failure instead. |
| `error[E0425]: cannot find function` + `windows_sys` in Specter cross-compile | 05, 06, 07, 08 | red-cell-c2-as0gd | 2026-04-27 | Relocated imports to windows-sys 0.59 module paths. E0425 resolved, but 138 new errors. **NEW ERROR** — see red-cell-c2-z85a3 |

---

## Pattern guidance for new entries

- *Signature* must be a **literal substring** that appears in the scenario's
  error / stderr / failure-diagnostic file.  No regexes, no paraphrasing —
  the agent should be able to `grep -F` for it.
- *Scenario* lists every scenario number that exhibits this pattern,
  comma-separated.  Range syntax (`12–24`) is fine for contiguous runs.
- *Bead* uses the full `red-cell-c2-XXXXX` slug.  *(no bead)* is valid for
  things fixed inline without a bead.
- *Status* one of: `P0–P4`, optionally with `in progress` / `blocked on X`.
  Resolved rows omit Status, populate `Resolved at` and `Notes` instead.
