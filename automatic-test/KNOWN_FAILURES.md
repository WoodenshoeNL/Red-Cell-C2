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
| `[TIMEOUT] timeout: timed out waiting for output from task` | 04, 05, 07, 19, 21, 23 | red-cell-c2-4vogq | 2026-04-28 | 2026-04-28 | P1, cross-agent task-output regression after acceptance (Demon + Phantom) |
| `CLI subprocess did not exit within expected timeout (40s)` | 11 | red-cell-c2-4vogq | 2026-04-28 | 2026-04-28 | (same task-output family; CLI wait path hangs instead of returning task timeout cleanly) |
| `Timed out after 30s waiting for remote upload /tmp/rc-test/uploaded-` | 06 | red-cell-c2-roz1h | 2026-04-28 | 2026-04-28 | P2, Phantom upload accepted but file never appears on target |
| `Timed out after 30s waiting for screenshot loot entry` | 08 | red-cell-c2-dn3yy | 2026-04-28 | 2026-04-28 | P2, runtime screenshot/loot failure on first failing Windows baseline pass |
| `Timed out after 30s waiting for 10 new agent checkins` | 14 | red-cell-c2-4302s | 2026-04-28 | 2026-04-28 | P1, Windows Demon stress deploy never yields expected registrations |
| `Timed out after 60s waiting for agent checkin` | 17 | red-cell-c2-4302s | 2026-04-28 | 2026-04-28 | (same Windows deploy/checkin regression for Archon single-agent baseline) |
| `last_seen never changed from initial '` | 24 | red-cell-c2-dz867 | 2026-04-28 | 2026-04-28 | P2, Phantom heartbeat/sleep-cadence regression after initial checkin |

---

## Resolved

Failures whose bead has been closed or whose root cause was fixed inline.
Kept for ~14 days so a regression is detected as a fix-didn't-stick rather
than a new bug.

| Signature (substring of error / stderr) | Scenario | Bead | Resolved at | Notes |
|----------------------------------------|----------|------|-------------|-------|
| `panic` + `TypeId` + `payload build-wait` clap collision | 03 | red-cell-c2-2edsr | 2026-04-26 | Renamed `BuildWait --output` → `--dst` to avoid TypeId collision with global `--output` (commit 71d115df) |
| Listener create fails: `address already in use` on 19081 / 19082 | 04, 05, 06, 07, 08, 11 | *(no bead — fixed inline)* | 2026-04-26 | `test.py` now stops + deletes leftover non-default listeners before scenarios start (commit 311d6253) |
| HTTP 429 / rate-limit cascade after scenarios 01–11 | 12–24 | *(no bead — fixed inline)* | 2026-04-26 | `profiles/autotest.yaotl` `RateLimitPerMinute` raised 120 → 600 (commit 311d6253) |
| `[INVALID_ARGS] unknown format 'elf': expected exe, dll, or bin` | 04, 06, 07, 11, 15, 21–24 | *(no bead — fixed inline)* | 2026-04-24 | Replaced `fmt='elf'` with `fmt='exe'` for Phantom (commit 9cddb9a5) |
| `not reachable via SSH` against the Windows VM despite `whoami` working | every scenario with `[windows]` configured | red-cell-c2-3jlpo | 2026-04-24 | `preflight_ssh` sent `true`, which `cmd.exe` does not know — switched to `exit 0` (commit c6fb4086) |
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
| `Address already in use (os error 98)` on port 19181/19182 from prior-run listeners | 04, 06, 07, 11, 17, 21–24 | red-cell-c2-hyhgf | 2026-04-27 | Preflight listener cleanup: resolve status, always stop before delete, multi-pass. Not seen this run. |
| `unparseable last_seen` (nanosecond timestamp with Z suffix) | 24 | *(no bead — fixed inline)* | 2026-04-27 | parse_last_seen now strips Z suffix and truncates nanoseconds to microseconds |
| `[TIMEOUT] timed out waiting for output from task` (wstring fix) | 04, 11, 21 | red-cell-c2-2g1nj | 2026-04-27 | Phantom wstring null terminator fix (commit eeead79c). **REGRESSED** — see red-cell-c2-asy66 |
| `Timed out after 60s waiting for agent checkin` (Invoke-WmiMethod fix) | 14, 17, 19 | red-cell-c2-gxabx | 2026-04-27 | Switched to Invoke-WmiMethod for Windows deploy. Process survives SSH, but agents still don't check in. **REGRESSED** — see red-cell-c2-db6yd |
| `error[E0425]: cannot find function` + `windows_sys` in Specter cross-compile | 05, 06, 07, 08 | red-cell-c2-as0gd | 2026-04-27 | Relocated imports to windows-sys 0.59 module paths. E0425 resolved, but 138 new errors (E0308, unsafe). **NEW ERROR** — see red-cell-c2-z85a3 |
| `still present in agent list after 120s — expected implant to stop after kill-date` | 22, 23 | red-cell-c2-dv5ev | 2026-04-27 | Phantom pre-init kill-date + working-hours checks + build.rs rerun-if-env-changed. Scenarios 22/23/24 now pass. |
| `[TIMEOUT] timeout: timed out waiting for output from task` (wstring null-terminator follow-up) | 04, 11, 21 | red-cell-c2-asy66 | 2026-04-27 | Phantom run loop retry/callback-send fix landed, but the timeout family still regressed the next day. **REGRESSED** — see red-cell-c2-4vogq |
| `Timed out after 60s waiting for agent checkin` (listener wiring / WMI follow-up) | 14, 17, 19 | red-cell-c2-db6yd | 2026-04-27 | Listener name now reaches API/CLI and scenario 19 no longer fails at listener attribution, but Windows deploy/checkin still regressed. **REGRESSED** — see red-cell-c2-4302s |
| `cargo build --release --target x86_64-pc-windows-gnu` + `error[E0308]` in Specter | 05, 06, 07, 08 | red-cell-c2-z85a3 | 2026-04-27 | Specter cross-compile fixes landed; this build failure was not seen in the 2026-04-28 run. |

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
