# BOF Output Persistence Fix

**Date:** 2026-07-21  
**Commit:** `e4fcf358`  
**Agent:** Desktop (Anvil)  
**Component:** `teamserver/src/dispatch/assembly.rs`, `teamserver/src/dispatch/dispatcher_registration_commands.rs`

## Problem

BOFs executed through Specter produced output (confirmed via `output_len=5312` in 
the agent trace), but the output never appeared at the teamserver's 
`GET /agents/{id}/output` API endpoint or via `red-cell-cli agent output`.

The agent was sending the BOF callbacks correctly as `CommandInlineExecute` 
responses. The teamserver received them and broadcast events to connected 
operators (WebSocket/CLI sessions). But the output was NOT persisted to the 
database, so it was invisible to anyone querying the REST API after the fact.

## Root Cause

The `handle_inline_execute_callback` function only took `&EventBus` as a 
parameter. It called `events.broadcast()` directly, bypassing the database 
entirely. Compare with `handle_command_output_callback` (shell command output) 
which uses `broadcast_and_persist_agent_response` — a function that both 
broadcasts an event AND writes the response to the `agent_responses` table.

The `GET /agents/{id}/output` endpoint reads exclusively from 
`agent_responses`. Without persistence, BOF output was lost after the event 
was broadcast.

## Fix

Three changes:

### 1. `teamserver/src/dispatch/assembly.rs`

Updated `handle_inline_execute_callback` to accept `&AgentRegistry` and 
`&Database`, and call `broadcast_and_persist_agent_response` instead of 
`events.broadcast()`:

```rust
// OLD (event-only, no persistence):
events.broadcast(agent_response_event(agent_id, command_id, request_id, kind, &message, None)?);

// NEW (broadcast + persist):
broadcast_and_persist_agent_response(
    database, events,
    AgentResponseEntry {
        agent_id,
        command_id: u32::from(DemonCommand::CommandInlineExecute),
        request_id,
        kind: kind.to_owned(),
        message: message.clone(),
        extra: Default::default(),
        output: output_text.clone().unwrap_or_default(),
    },
    &context,
).await?;
```

The `output_text` field carries the actual BOF output for 
`BOF_CALLBACK_OUTPUT` and `BOF_CALLBACK_ERROR` callbacks. For other callback 
types (exception, symbol not found, ran ok, could not run), `output` is empty 
and the details are in `message`.

### 2. `teamserver/src/dispatch/dispatcher_registration_commands.rs`

Updated the handler registration to clone and pass `registry` + `database` 
to the `CommandInlineExecute` handler closure.

### 3. Test updates

- `teamserver/src/dispatch/tests/common.rs`: Added `test_db_registry()` helper 
  that creates an in-memory `Database` + `AgentRegistry` pair.
- `teamserver/src/dispatch/tests/assembly.rs`: Updated all 11 test functions to 
  use the new signature. Tests that call `broadcast_and_persist_agent_response` 
  now seed a test agent in the registry (FK constraint on `agent_id`).
- `teamserver/src/dispatch/tests/process/assembly.rs`: Updated the assertion for 
  `BOF_CALLBACK_OUTPUT` from `Type="Output"` to `Type="Good"` and the message 
  format from the raw output text to `"Received BOF Output [N bytes]:"`.

## Verification

Before fix: `GET /agents/{id}/output` → `{"total":0,"entries":[]}` despite 
the agent producing 5312 bytes of BOF output.

After fix:
```
GET /agents/A354477B/output →
{
  "total": 31,
  "entries": [
    {"message": "Received BOF Output [5312 bytes]:", "output": "\nUserName\t\tSID\n..."},
    {"message": "BOF execution completed"},
    ...
  ]
}
```

CLI: `red-cell-cli agent output A354477B` shows full BOF output including 
whoami user/SID/groups, ARP tables, IP config, DNS cache, firewall rules 
(308KB), environment variables, and more.

Test setup:
- Agent: Specter `A354477B` on Windows test VM (192.168.50.15, Windows 10 x64 build 26200)
- C2: Red-Cell-C2 teamserver (192.168.50.48:40056 API + :19100 HTTP listener)
- 16 no-arg BOFs tested, 15/16 produced real output (notepad is a test stub)
