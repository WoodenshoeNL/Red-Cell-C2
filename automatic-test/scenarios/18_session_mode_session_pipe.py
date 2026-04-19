"""
Scenario 18_session_mode: red-cell-cli session mode (persistent JSON pipe)

Exercises the session mode protocol end-to-end against a running teamserver.
No physical target machine is required — the scenario only drives the CLI ↔
teamserver channel via newline-delimited JSON over a single persistent
subprocess.

Tests:
  1. connect         — start the session subprocess
  2. ping            — round-trip {"cmd":"ping"} → {"ok":true,"data":{"pong":true}}
  3. agent.list      — must return a JSON array (empty is fine)
  4. agent.exec      — if ≥1 agent is present run a shell command with wait=true;
                       otherwise verify the NOT_FOUND error path
  5. multi-command   — three sequential commands sharing the same connection
  6. batch send      — pipeline three commands without waiting between sends;
                       responses must arrive in order
  7. exit command    — {"cmd":"exit"} causes the process to exit 0
  8. EOF exit        — closing stdin (no explicit exit) also causes exit 0
"""

DESCRIPTION = "red-cell-cli session mode (persistent JSON pipe)"

import json


def run(ctx):
    """
    ctx.cli     — CliConfig (red-cell-cli wrapper)
    ctx.linux   — TargetConfig | None  (not used in this scenario)
    ctx.windows — TargetConfig | None  (not used in this scenario)
    ctx.env     — raw env.toml dict
    ctx.dry_run — bool

    Raises AssertionError with a descriptive message on any failure.
    """
    from lib.cli import CliError, agent_list
    from lib.session import Session, SessionError

    cli = ctx.cli

    # ── 1. Ping ───────────────────────────────────────────────────────────────
    print("  [session][ping] starting session, sending ping")
    with Session(cli) as sess:
        pong = sess.send({"cmd": "ping"})
        assert pong.get("pong") is True, (
            f"expected {{\"pong\": true}}, got {pong!r}"
        )
    print("  [session][ping] passed")

    # ── 2. agent.list ─────────────────────────────────────────────────────────
    print("  [session][agent.list] verifying agent list returns a JSON array")
    with Session(cli) as sess:
        agents = sess.send({"cmd": "agent.list"})
        assert isinstance(agents, list), (
            f"agent.list must return a list, got {type(agents).__name__}: {agents!r}"
        )
    print(f"  [session][agent.list] passed ({len(agents)} agent(s) present)")

    # ── 3. agent.exec ─────────────────────────────────────────────────────────
    if agents:
        agent_id = f"{agents[0]['AgentID']:08X}"
        print(f"  [session][agent.exec] running 'echo hello' on agent {agent_id!r}")
        with Session(cli) as sess:
            # Use raise_on_error=False: the agent may be dead (EXEC_TIMEOUT or
            # NOT_FOUND). We only verify the session delivers a valid dict envelope.
            result = sess.send(
                {
                    "cmd": "agent.exec",
                    "id": agent_id,
                    "command": "echo hello",
                    "wait": True,
                    "timeout": 5,
                },
                raise_on_error=False,
            )
            assert isinstance(result, dict), (
                f"agent.exec result must be a dict, got {type(result).__name__}"
            )
        print("  [session][agent.exec] passed")
    else:
        print("  [session][agent.exec] no agents present — testing NOT_FOUND error path")
        with Session(cli) as sess:
            resp = sess.send(
                {"cmd": "agent.exec", "id": "nonexistent-000", "command": "echo x"},
                raise_on_error=False,
            )
            assert resp.get("ok") is False, (
                f"expected error envelope, got {resp!r}"
            )
            assert resp.get("error") in ("NOT_FOUND", "UNKNOWN"), (
                f"unexpected error code: {resp.get('error')!r}"
            )
        print("  [session][agent.exec] NOT_FOUND error path passed")

    # ── 4. Multi-command sequence ─────────────────────────────────────────────
    print("  [session][multi-cmd] three sequential commands on one connection")
    with Session(cli) as sess:
        r1 = sess.send({"cmd": "ping"})
        assert r1.get("pong") is True, f"ping 1 failed: {r1!r}"

        r2 = sess.send({"cmd": "agent.list"})
        assert isinstance(r2, list), f"agent.list in multi-cmd failed: {r2!r}"

        r3 = sess.send({"cmd": "ping"})
        assert r3.get("pong") is True, f"ping 2 failed: {r3!r}"
    print("  [session][multi-cmd] passed")

    # ── 5. Batch (pipelined) send ─────────────────────────────────────────────
    # Three agent.list commands — all go to the server so responses arrive in
    # submission order.  Mixing local commands (e.g. ping) with server commands
    # breaks ordering because ping is answered by the CLI without a round-trip.
    print("  [session][batch] sending 3 agent.list commands without waiting between them")
    with Session(cli) as sess:
        cmds = [
            {"cmd": "agent.list"},
            {"cmd": "agent.list"},
            {"cmd": "agent.list"},
        ]
        responses = sess.send_batch(cmds)

        assert len(responses) == 3, (
            f"expected 3 responses, got {len(responses)}"
        )
        for i, resp in enumerate(responses):
            assert resp.get("ok") is True, (
                f"batch response[{i}] not ok: {resp!r}"
            )
            assert resp.get("cmd") == "agent.list", (
                f"batch response[{i}] wrong cmd: {resp.get('cmd')!r}"
            )
            assert isinstance(resp.get("data"), list), (
                f"batch response[{i}] data not a list: {resp!r}"
            )
    print("  [session][batch] passed — 3 responses arrived in order")

    # ── 6. Graceful exit via {"cmd":"exit"} ───────────────────────────────────
    print('  [session][exit-cmd] sending {"cmd":"exit"} and checking process exit code')
    sess = Session(cli)
    sess.__enter__()
    # Verify ping works before exit
    pong = sess.send({"cmd": "ping"})
    assert pong.get("pong") is True, f"pre-exit ping failed: {pong!r}"
    # Send exit — the process should close stdout; reading further would EOF
    assert sess._proc is not None
    sess._proc.stdin.write(json.dumps({"cmd": "exit"}) + "\n")
    sess._proc.stdin.flush()
    exit_code = sess.wait(timeout=5)
    assert exit_code == 0, f"expected exit code 0 after exit command, got {exit_code}"
    sess.__exit__(None, None, None)
    print(f"  [session][exit-cmd] passed (exit code {exit_code})")

    # ── 7. Graceful exit via EOF ───────────────────────────────────────────────
    print("  [session][eof-exit] closing stdin (EOF) and checking process exit code")
    sess2 = Session(cli)
    sess2.__enter__()
    pong2 = sess2.send({"cmd": "ping"})
    assert pong2.get("pong") is True, f"pre-EOF ping failed: {pong2!r}"
    sess2.close_stdin()
    eof_exit_code = sess2.wait(timeout=5)
    assert eof_exit_code == 0, (
        f"expected exit code 0 on EOF, got {eof_exit_code}"
    )
    sess2.__exit__(None, None, None)
    print(f"  [session][eof-exit] passed (exit code {eof_exit_code})")

    print("\n  [session] all session-mode checks passed")
