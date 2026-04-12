//! `red-cell-cli session` — persistent NDJSON WebSocket pipe.
//!
//! Establishes a single authenticated WebSocket connection to the teamserver's
//! `/api/v1/ws` endpoint and relays newline-delimited JSON between stdin and
//! the server.  Successful responses are written to stdout; failures (including
//! locally rejected commands) go to stderr, consistent with the global CLI
//! contract.
//!
//! # Authentication
//!
//! The operator API token is injected into the `x-api-key` header of the HTTP
//! upgrade request.  This is the same token used by the REST API — no separate
//! login step is required.
//!
//! # Transport
//!
//! A single WebSocket connection is opened at session start and kept alive for
//! the lifetime of the session.  All commands travel over this one connection,
//! preserving connection semantics (authentication, rate limiting) and
//! eliminating per-command TCP/TLS overhead.
//!
//! The teamserver session endpoint is tracked in issue `red-cell-c2-9ebj4`
//! (zone:teamserver).
//!
//! # Protocol
//!
//! **stdin** — one JSON object per line:
//! ```json
//! {"cmd": "agent.exec", "id": "abc123", "command": "whoami", "wait": true}
//! ```
//!
//! **stdout** — success responses, one JSON object per line:
//! ```json
//! {"ok": true,  "cmd": "agent.exec", "data": {"output": "DOMAIN\\user", "exit_code": 0}}
//! ```
//!
//! **stderr** — error responses, one JSON object per line:
//! ```json
//! {"ok": false, "cmd": "agent.exec", "error": "NOT_FOUND", "message": "agent not found"}
//! ```
//!
//! The session terminates on:
//! - EOF on stdin
//! - `{"cmd": "exit"}`
//! - Server closing the WebSocket connection
//! - Ctrl-C
//!
//! # Locally handled commands
//!
//! | `cmd`  | Behaviour                                  |
//! |--------|--------------------------------------------|
//! | `ping` | Answered immediately; no server round-trip |
//! | `exit` | Sends WS close frame and exits cleanly     |
//!
//! Any other `cmd` must match a known session command (same names as the
//! `red-cell-cli` surface and the teamserver session router).  Unknown
//! commands produce a single local JSON line on **stderr** (same `ok`/`cmd`/
//! `error`/`message` envelope as other session errors) and are not sent to the
//! server:
//! ```json
//! {"ok": false, "cmd": "agent.lst", "error": "UNKNOWN_COMMAND", "message": "unknown command `agent.lst`"}
//! ```
//!
//! All recognised commands are forwarded to the server unchanged.
//!
//! # Default agent
//!
//! When `--agent <id>` is passed to `red-cell-cli session`, the session injects
//! the agent id into any incoming command that has no `"id"` field before
//! forwarding it to the server.

mod connect;
mod io;
mod normalize;
mod run;

pub use run::run;
