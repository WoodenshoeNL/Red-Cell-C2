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
| `TCP-remote=(none)` + `(no candidate archon-http.txt exists)` + `Timed out after 60s waiting for agent checkin` (Archon regression — Demon crash-guard removed in c58b68ea; WerFault.exe spawns in Session 0, blocks on AMSI, preventing Archon init; zombie Archon processes from timed-out sc05-08 passes accumulate) | 05, 06, 07, 08, 17 | red-cell-c2-lz95k | 2026-05-14 | 2026-05-14 | P1 |
| `os error 10055` + `tcp connect error: An operation on a socket could not be performed` (Specter DoH sc20, all TCP connections fail immediately — accumulated WerFault.exe processes + zombie Archon processes from prior timed-out passes exhaust socket/buffer resources; correlated with Demon crash-guard removal c58b68ea) | 20 | red-cell-c2-uvi3e | 2026-05-14 | 2026-05-14 | P2 |
---

## Resolved

Failures whose bead has been closed or whose root cause was fixed inline.
Kept for ~14 days so a regression is detected as a fix-didn't-stick rather
than a new bug.

| Signature (substring of error / stderr) | Scenario | Bead | Resolved at | Notes |
|----------------------------------------|----------|------|-------------|-------|
| `RCTEST_SCHTASK_STATE:Running` + `Timed out after 60s waiting for agent checkin` OR `os error 10055` OR `[SUBPROCESS_TIMEOUT]` (WFP non-paged pool exhaustion from zombie FWPM_GENERAL_CONTEXT objects — New-NetFirewallRule and Set-MpPreference per-run calls left orphaned WFP provider contexts; fixed by stopping New-NetFirewallRule calls, disabling Windows Firewall on test VM, raising WFP_RESTART_THRESHOLD to 5500) | 05, 06, 08, 17, 20 | red-cell-c2-lnsjt | 2026-05-11 | WFP pool exhaustion root cause fixed (commits 3aef58a4, 497499cd, 7841e688, 5edf5489). WFP counts now stable at 4183–4190 baseline throughout full runs. Remaining Windows failures tracked in qqi66 (Demon crash cascade), ov4zg (netstat hang). |
| `TCP-remote=(none)` + `(no candidate archon-http.txt exists)` + `Timed out after 60s waiting for agent checkin` (Archon-only, S4U session: LoadDecoyModule loaded amsi.dll via LdrModuleLoad during DemonInit; AMSI provider DllMain blocks indefinitely in Session 0 — agent hangs before TransportInit) | 17 | red-cell-c2-1adeu | 2026-05-14 | Prefer already-loaded Runtime modules (sspicli, iphlpapi, gdi32, shell32) as PE header decoy; fall back to amsi.dll only if none have valid PE headers (commit 440300e5). sc17 passes on 2026-05-14 targeted run. |
| `APPCRASH` + `stress-agent-` OR (`RCTEST_SCHTASK_STATE:Running` + `TCP-remote=(none)` + `os error 10055`) (Demon crashes on kill → WER holds crash handles consuming non-paged pool → subsequent Windows agents can't allocate sockets) | 05, 06, 08, 17, 20 | red-cell-c2-qqi66 | 2026-05-11 | VEH crash guard + NtContinue fallback + WER disable eliminated crash-dump pool exhaustion (run_083134_266fbee7 2026-05-11: no new APPCRASHes, no os error 10055, sc05/06/07/08/14/20 all pass). |
| `sleep process PID` + `not found in tasklist after 5 attempts` (Start-Process returns a PID that vanishes before tasklist can see it — SSH Job Object kills the process on disconnect) | 07 | red-cell-c2-dckv2 | 2026-05-11 | Replaced Start-Process with WMI Win32_Process.Create (spawns outside SSH Job Object); increased retry from 5 to 8 attempts. Closed 2026-05-11. |
| `[SUBPROCESS_TIMEOUT] CLI subprocess did not exit within expected timeout (55s)` + `netstat -ano` (Demon hangs on netstat -ano; fixed by replacing with netstat -a -n -p TCP, removing PID lookup that triggered WFP pool pressure) | 05, 07 | red-cell-c2-ov4zg | 2026-05-10 | Replaced `netstat -ano` with `netstat -a -n -p TCP` in sc05/sc07/sc09. Closed 2026-05-10. |
| `RCTEST_SCHTASK_STATE:Ready` + `RCTEST_SCHTASK_LASTTASKRESULT:267011` + `RCTEST_SCHTASK_LASTRUNTIME:1999-11-30` (schtask Interactive→S4U fallback misses State='Ready'; task never runs) | 05, 06, 07, 08, 14, 17, 19, 20 | red-cell-c2-j3hxi | 2026-05-10 | Fixed inline in deploy.py: trigger S4U fallback when State=='Ready' AND LastTaskResult==267011 in addition to State=='Queued'. Closed 2026-05-10. WFP pool exhaustion (lnsjt) is now the new blocker for Windows scenarios. |
| `SSH to 192.168.213.160 failed (attempt 1/3), retrying in 2s` (Windows VM unreachable via TCP timeout; globally-unreachable registry now short-circuits per-scenario preflight_ssh) | all Windows-touching | red-cell-c2-1nnzz | 2026-05-09 | Fixed: mark_host_unreachable() registry added in deploy.py; preflight_ssh raises ScenarioSkipped immediately for globally-unreachable hosts, eliminating 3×ConnectTimeout retry overhead. |
| `[between-scenarios] cleanup skipped (192.168.213.160): SSH to 192.168.213.160 failed after 3 attempts` (wfp_preflight_cleanup + cleanup_windows_harness_work_dir not checking _globally_unreachable_hosts — each between-scenario call took 34s when Windows VM was down, adding ~26 min overhead for 23-scenario runs) | all | *(fixed inline)* | 2026-05-10 | Added `if target.host in _globally_unreachable_hosts: return None/early` to wfp_preflight_cleanup and cleanup_windows_harness_work_dir in lib/deploy.py; between-scenario calls now skip immediately when Windows is globally-unreachable. Run time cut from ~41 min to ~13 min when Windows is down. |
| `~ SKIPPED (34.1s): SSH to 192.168.213.160 failed after 3 attempts` (sc08 Linux/Phantom fallback not tried when Windows SSH unreachable — ScenarioSkipped not caught alongside DeployError) | 08 | red-cell-c2-a4s1b | 2026-05-10 | Fixed: catch `(DeployError, ScenarioSkipped)` in sc08 preflight block so the Linux/Phantom path runs when Windows is globally-unreachable. sc08 passes 2026-05-10 with Phantom screenshot verified. |
| `~ SKIPPED (0.0s): target 192.168.213.160 was unreachable at startup — skipping SSH probe` (sc14 Phantom stress pass skipped when Windows SSH unreachable — same DeployError vs ScenarioSkipped gap as a4s1b) | 14 | *(fixed inline)* | 2026-05-10 | Catch `(DeployError, ScenarioSkipped)` in sc14 Demon preflight block so the Phantom Linux stress pass runs when Windows is globally-unreachable. |
| `Timed out after 60s waiting for 10 agents` (sc14 Demon pass timed out when WFP pool critically exhausted — sc14 did not check ctx.windows_degraded before launching Demon stress agents; SSH to Windows worked but agents couldn't reach C2 server) | 14 | *(fixed inline)* | 2026-05-10 | Added `ctx.windows_degraded` guard to sc14 Demon pass determination; Demon pass now skips when WFP pool is critically exhausted, falling through to Phantom Linux pass. Unit test added in tests/test_scenario_14_stress.py. |
| `Timed out after 30s waiting for screenshot loot entry` (Phantom/Linux, DISPLAY not set in agent exec env) | 08 | red-cell-c2-desrw | 2026-05-09 | Two-layer fix: execute_background propagates env_vars, sc08 injects DISPLAY=display for Phantom; Phantom also probes :0/:99/:1 fallback. Bead closed 2026-05-09; sc08 passes 2026-05-10 via Linux Phantom fallback. |
| `Linux target configured but no available Linux agent (add 'phantom' to agents.available)` (unit test test_phantom_skipped_when_not_in_available missing preflight_ssh patch) | unit test | *(fixed inline)* | 2026-05-09 | Added `patch("lib.deploy.preflight_ssh")` to TestScenario14.test_phantom_skipped_when_not_in_available; preflight_ssh was added to sc14 run() in commit 275fdf59 but the unit test wasn't updated. |
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
| `[TIMEOUT] timeout: timed out waiting for output from task` + `Exec round 2 failures` (Phantom stress, 1/5 agents timeout under concurrent load — CTR desync via COMMAND_CHECKIN send / per-task callback / flush_pending_callbacks) | 14 | red-cell-c2-n4kr4 | 2026-05-14 | Fixed: advance CTR/seq unconditionally in COMMAND_CHECKIN send, per-task callback loop, and flush_pending_callbacks (2026-05-14). Remaining gap tracked as red-cell-c2-bviim (non-ECONNREFUSED pre-connect paths). |
| `[TIMEOUT] timeout: timed out waiting for output from task` + `Exec round 2 failures` (Phantom stress, sc14 concurrent load — pre-connect failure CTR/seq desync; non-ECONNREFUSED paths still advance CTR when server never received packet) | 14 | red-cell-c2-bviim | 2026-05-14 | Broadened pre-connect failure classification from ECONNREFUSED-only to all connect-phase errors via reqwest::Error::is_connect(). Renamed ConnectionRefused to PreConnectFailure. Regression tests added. Closed 2026-05-14. |
| `Timed out after 60s waiting for agent checkin` (Phantom Linux, fresh deploy after sc14 stress — agent never connected, VM overload cascade from sc14 lingering agents) | 21 | red-cell-c2-fmmxa | 2026-05-14 | Fixed: 90s checkin_timeout floor for sc21, inter-scenario drain (5s, configurable), SSH process-existence probe in deploy_and_checkin, inter_scenario_drain_secs to env.toml files (2026-05-14). |
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
| `The string is missing the terminator: '.` | 06 | *(fixed inline)* | 2026-05-03 | Fixed PowerShell `certutil -hashfile` quoting in `automatic-test/scenarios/06_file_transfer_file_transfer.py`; rerun moved sc06 to the underlying Phantom upload timeout instead of the parser error. |

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
