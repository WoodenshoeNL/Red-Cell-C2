# Automated Test Harness

The harness drives the full `red-cell-cli → teamserver → agent` flow against real
target machines. All interaction goes through `red-cell-cli` (JSON output, stable
exit codes) so AI agents can run it unattended and file bugs for failures.

## Structure

```
automatic-test/
  test.py                     # main runner: --scenario all|01|02|...
  config/
    env.toml                  # teamserver URL + operator credentials — GITIGNORED
    env.toml.example          # template with placeholders (callback_host commented)
    targets.toml              # test-machine SSH details — GITIGNORED
    targets.toml.example      # template with placeholders
  scenarios/
    01_auth.py                # login, token expiry, RBAC enforcement
    02_listeners.py           # HTTP/DNS/SMB create/start/stop/delete
    03_payload_build.py       # all format × arch combos, PE validation
    04_agent_linux.py         # deploy → checkin → command suite on Ubuntu
    05_agent_windows.py       # deploy → checkin → command suite on Windows 11
    06_file_transfer.py       # upload + download round-trip
    07_process_ops.py         # list, kill, inject
    08_screenshot.py          # screenshot capture + loot entry
    09_kerberos.py            # token operations
    10_pivot.py               # pivot chain dispatch
    11_loot_audit.py          # loot entries, audit log completeness
    12_rbac.py                # role enforcement across all endpoints
  lib/
    cli.py                    # subprocess wrapper for red-cell-cli
    deploy.py                 # SSH/SCP helpers (Linux + Windows)
    wait.py                   # poll helpers: wait_for_agent, wait_for_output
  PROMPTS/
    AGENT_TEST_PROMPT.md      # prompt for AI-agent-driven test runs
```

## Running

```bash
cd automatic-test

# Run all scenarios against both targets
python3 test.py --scenario all

# Run a single scenario
python3 test.py --scenario 04

# Dry-run (validate config only, no actual deployment)
python3 test.py --dry-run
```

## Target machines

| Target | OS | Deploy method |
|--------|----|---------------|
| `linux-test` | Ubuntu Desktop (latest LTS) | SSH + SCP |
| `windows-test` | Windows 11 | SSH (OpenSSH for Windows) |

Connection details live in `automatic-test/config/targets.toml` (gitignored).
See `automatic-test/config/targets.toml.example` for the required fields.

Teamserver URL, operator credentials, and the host-specific `callback_host`
live in `automatic-test/config/env.toml` (gitignored). `test.py` auto-seeds
it from `env.toml.example` on first run, but `callback_host` must be set
manually before scenarios that deploy agents to remote targets will pass.

For Windows SSH setup, see `docs/win11-ssh-setup.md`.

## Manual test plan

A checklist-style test plan for operator-driven validation lives in
`docs/test-plan.md`. It covers every layer: auth, listeners, payload generation,
agent commands, events, loot, plugins, and the REST API.
