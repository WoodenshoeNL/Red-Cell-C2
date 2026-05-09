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
| `Timed out after 30s waiting for screenshot loot entry` (Phantom/Linux, DISPLAY not set in agent exec env) | 08 | red-cell-c2-desrw | 2026-05-09 | 2026-05-09 | P2 |

---

## Resolved

Failures whose bead has been closed or whose root cause was fixed inline.
Kept for ~14 days so a regression is detected as a fix-didn't-stick rather
than a new bug.

| Signature (substring of error / stderr) | Scenario | Bead | Resolved at | Notes |
|----------------------------------------|----------|------|-------------|-------|
| `Remote command failed (exit 255)` + `ssh: connect to host 192.168.213.160 port 22: No route to host` (sc14 Demon pass with Windows VM unreachable) | 14 | *(fixed inline)* | 2026-05-09 | Added `preflight_ssh(ctx.windows)` check before Demon pass in sc14; DeployError now converts to a skipped Demon pass rather than a hard scenario failure. Phantom pass still runs when Linux is available. |
| `Timed out after 60s waiting for agent checkin` / `[SUBPROCESS_TIMEOUT]` (Windows passes in sc06/07/08, WFP ~6390+) | 06, 07, 08 | red-cell-c2-5wu5u | 2026-05-09 | Closed: propagated windows_degraded into RunContext; sc06/07/08 skip Windows passes when WFP pool is exhausted, preserving Linux-agent pass coverage. |
| `Timed out after 60s waiting for agent checkin` (sc04 only, no teamserver entries) | 04 | red-cell-c2-2frr8 | 2026-05-09 | Closed: added init_handshake_with_retry (3 attempts, 2s backoff) in run_loop.rs. sc04 passes 2026-05-09. |
| `audit filter --agent: filtered result multiset mismatch` | 11 | red-cell-c2-d0amv | 2026-05-09 | Closed: added until=audit_window_end to all three log_list() filter calls (--operator/--action/--agent). sc11 passes 2026-05-09. |
| `cargo build --release --target x86_64-pc-windows-gnu` + `error[E0432]` + `NetSessionEnum` + `SESSION_INFO_10` | 20 | red-cell-c2-ikwhx | 2026-05-09 | Closed: moved NetSessionEnum/SESSION_INFO_10 to Win32::Storage::FileSystem in windows-sys 0.59 (commit ee9597c6). sc20 build succeeds 2026-05-09; sc20 still fails for WFP/socket reasons. |
| `[SUBPROCESS_TIMEOUT]`/`os error 10055`/`Timed out after 60s waiting for agent checkin` (Archon/WFP, sc05/06/07/08/17/20) | 05, 06, 07, 08, 17, 20 | red-cell-c2-gnn1n | 2026-05-09 | Closed: added wfp_critical flag + scenario-loop skip for WINDOWS_REQUIRED scenarios. Bug in this fix (wfp_critical not returned when mpssvc refuses restart) fixed inline (red-cell-c2-06gbu). sc06/07/08 still fail — see red-cell-c2-5wu5u. |
| `wfp_critical not set when mpssvc restart exits non-zero` | 05, 06, 07, 08, 17, 20 | red-cell-c2-06gbu | 2026-05-09 | Fixed inline: wfp_critical=True now returned when restart_result.returncode != 0 AND wfp_observed >= threshold. Unit test added (test_wfp_critical_set_when_mpssvc_restart_refused_by_os). |
| `[SUBPROCESS_TIMEOUT]`/`os error 10055`/`Timed out after 60s waiting for agent checkin` (Archon/WFP) | 05, 06, 07, 08, 17, 20 | red-cell-c2-gdiw8 | 2026-05-09 | Closed: added between-pass WFP cleanup + wfp=/twait= diagnostics + mpssvc restart (72c10a67/74c27b43/cirdt/lxfdz). Regression confirmed same day — mpssvc restart does not reduce wfp=6393; see red-cell-c2-gnn1n. |
| `Timed out after 30s waiting for screenshot loot entry` (demon hash + WinSta0 fix) | 08 | red-cell-c2-uzl9i | 2026-05-08 | Closed: fixes (8bf46ce2, c5463122, 4023932a) moved from demon to archon (06346e50). New failure tracked as red-cell-c2-z5rl8 (Demon pass reverted; Archon pass needs verification). |
| `Timed out after 30s waiting for screenshot loot entry` (Demon pass skipped in SC08) | 08 | red-cell-c2-z5rl8 | 2026-05-08 | Closed: sc08 now skips Demon pass unconditionally (Demon screenshot not maintained since 06346e50 revert); Archon runs as primary. ScenarioSkipped raised when neither archon nor specter is in agents.available. |
| `[TIMEOUT] timeout: timed out waiting for output from task` (Phantom CTR/seq fix) | 04, 06, 07, 08, 11, 21 | red-cell-c2-1f7q1 | 2026-05-06 | Closed and split into lkkaq (root cause: CTR desync in get_job()) + 0xpyf (fix: advance CTR/seq unconditionally, commit 4a87b01d). Verified passing in run_073425 (sc04/sc21 pass). sc11 passes 2026-05-08. |
| `undefined reference to '__mingw_vsnprintf'` | 05, 06, 07, 08, 17 | red-cell-c2-cgzoo | 2026-05-02 | Removed snprintf + OutputDebugStringA from TransportHttp.c; Archon builds fine. |
| `audit operator mismatch: expected` | 11 | *(fixed inline)* | 2026-05-02 | audit_checks.py assert_operator_attribution allows agent.registered and agent.dead for teamserver. |
| `Timed out after 60s waiting for agent checkin` (Archon AmsiEtw fix) | 05, 06, 17 | red-cell-c2-vudj9 | 2026-05-07 | Closed via 9bzk8: moved AmsiEtwBypassPatch() after first successful TransportInit() + AmsiPatched flag (commit 4bcac689). sc17 now fails only under WFP pool exhaustion (see e8gv0). |
| `sleep process PID` ... `not found in tasklist immediately after spawn` | 07 | red-cell-c2-6sjhx | 2026-05-07 | Added 5-attempt retry loop (0.5s between attempts) for tasklist sanity check after SSH spawn (commit 9b7c5237). sc07 now fails at netstat-ano before reaching spawn check (WFP cascade). |
| `Timed out after 30s waiting for screenshot loot entry` (WinSta0+WinHTTP fix) | 08 | red-cell-c2-spxyy | 2026-05-08 | Closed: WinSta0\\Default thread-binding before GDI + 15 s WinHTTP timeouts (c5463122/b09f82d6). Fix predates last failing run — post-fix verification pending, see red-cell-c2-uzl9i. |
| `Timed out after 30s waiting for screenshot loot entry` (liveness fix) | 08 | red-cell-c2-l0dti | 2026-05-07 | Closed: handle_get_job refresh last_call_in (8ce9230c) + WinScreenshot virtual-screen fix (2323d7f3). **REGRESSED** — screenshot loot still absent 2026-05-08, see red-cell-c2-spxyy. |
| `invalid Demon packet size: declared 2286763818 bytes, actual 72 bytes` | 21, 22 | red-cell-c2-ya2cm | 2026-05-03 | CTR advance aligned with successful delivery + regression test. sc21/22 pass. |
| `agent kill failed (non-fatal): [SUBPROCESS_TIMEOUT] CLI subprocess did not exit within expected timeout (40s)` | 13, 20 | red-cell-c2-csyk0 | 2026-05-08 | sc13/sc20 cleanup now uses `--deregister-only` for synthetic protocol-probe agents (no real process; kill task never delivered); `agent_kill(deregister_only=True)` added to lib/cli.py. |
| `RCTEST_SCHTASK_LASTTASKRESULT:1` | 20 | red-cell-c2-idu5z | 2026-05-07 | Closed via ueufp: WFP cleanup in deploy_and_checkin try/finally (6c610873). Cross-run pool drain remains — see red-cell-c2-e8gv0. |
| `[SUBPROCESS_TIMEOUT] CLI subprocess did not exit within expected timeout (55s) (exit -1)` + `os error 10055` (WFP preflight-cleanup fix) | 05, 07, 20 | red-cell-c2-e8gv0 | 2026-05-08 | Closed: wfp_preflight_cleanup sweeps RC-Harness-*/agent-* firewall rules + NP ExclusionIpAddress draining (e80dd10c). Fix predates last failing run — post-fix verification pending, see red-cell-c2-gdiw8. |
| `No space left on device` | 22, 23 | red-cell-c2-sb5bm | 2026-05-02 | sccache cap set to 5 GB default; daemon stopped before cargo. sc22/23/24 pass. |
| `CLI log list since+until: filtered result multiset mismatch` | 11 | red-cell-c2-ycm9d | 2026-05-07 | Fixed _utc_now_iso() to microsecond precision (030c72b3). sc11 passes 2026-05-08. |
| `[TIMEOUT] timeout: timed out waiting for output from task` (AnonPipesInit pipe-inheritance fix) | 05, 07, 08, 14, 19 | red-cell-c2-32vg1 / red-cell-c2-ctbzd | 2026-05-07 | AnonPipesInit made read-end non-inheritable via DuplicateHandle; ProcessCreate closes parent write-end after CreateProcess. Commit b4d855b0. Demon cmd output now works; newly-exposed failures in sc07 (6sjhx) and sc08 (l0dti). |
| `Process could not be started: Path:[]` (cmd.exe /c wrapping fix) | 05, 14, 19 | red-cell-c2-2u0hw | 2026-05-02 | d42dfead wraps all shell commands in cmd.exe /c; DB notification not persisted for piped+success; bead closed. Path:[] symptom gone. **REGRESSED** — command output still doesn't return, see red-cell-c2-gscsb (timeout). |
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
| `The string is missing the terminator: '.` | 06 | *(fixed inline)* | 2026-05-03 | Fixed PowerShell `certutil -hashfile` quoting in `automatic-test/scenarios/06_file_transfer_file_transfer.py`; rerun moved sc06 to the underlying Phantom upload timeout instead of the parser error. |
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
