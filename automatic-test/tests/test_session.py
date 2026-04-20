"""
tests/test_session.py — Unit tests for lib/session.py.

All tests mock ``subprocess.Popen`` so no real binary or teamserver is needed.

Run with:  python3 -m unittest discover -s automatic-test/tests
       or: python3 -m pytest automatic-test/tests/test_session.py
"""

from __future__ import annotations

import io
import json
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

# Make automatic-test/ importable from repo root or from the test directory.
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.cli import CliConfig
from lib.session import Session, SessionError


# ── helpers ───────────────────────────────────────────────────────────────────

def _cfg(**kwargs) -> CliConfig:
    defaults = dict(server="http://localhost:40056", token="test-token")
    defaults.update(kwargs)
    return CliConfig(**defaults)


def _ok_envelope(cmd: str, data: object) -> str:
    return json.dumps({"ok": True, "cmd": cmd, "data": data}) + "\n"


def _err_envelope(cmd: str, code: str, message: str) -> str:
    return json.dumps({"ok": False, "cmd": cmd, "error": code, "message": message}) + "\n"


def _make_mock_proc(stdout_lines: list[str]) -> MagicMock:
    """Build a mock Popen object that yields *stdout_lines* one-by-one.

    Both stdout and stderr are mocked.  stderr always returns "" (EOF) so the
    reader thread exits immediately.  stdout pops lines from *stdout_lines*,
    returning "" when exhausted.
    """
    proc = MagicMock()
    proc.poll.return_value = None  # still running
    proc.wait.return_value = 0

    # stdin: accept writes without error
    proc.stdin = MagicMock()
    proc.stdin.__enter__ = lambda s: s
    proc.stdin.__exit__ = MagicMock(return_value=False)

    # stdout: readline() pops from the front of stdout_lines
    remaining = list(stdout_lines)

    def _readline():
        return remaining.pop(0) if remaining else ""

    proc.stdout = MagicMock()
    proc.stdout.readline.side_effect = _readline

    # stderr: always EOF so the background reader thread exits immediately
    proc.stderr = MagicMock()
    proc.stderr.readline.return_value = ""

    return proc


# ── Session.__enter__ / __exit__ ──────────────────────────────────────────────

class TestSessionContextManager(unittest.TestCase):
    def test_enter_starts_process(self) -> None:
        """__enter__ must call Popen with the right arguments."""
        proc = _make_mock_proc([_ok_envelope("ping", {"pong": True})])
        cfg = _cfg()

        with patch("subprocess.Popen", return_value=proc) as mock_popen:
            with Session(cfg) as sess:
                self.assertIs(sess._proc, proc)

        mock_popen.assert_called_once()
        call_args = mock_popen.call_args
        cmd = call_args[0][0]
        self.assertEqual(cmd[0], cfg.binary)
        self.assertIn("session", cmd)

    def test_enter_passes_agent_flag(self) -> None:
        """--agent flag must be appended when agent is provided."""
        proc = _make_mock_proc([])
        proc.poll.return_value = 1  # already exited — no exit cmd sent

        with patch("subprocess.Popen", return_value=proc) as mock_popen:
            with Session(_cfg(), agent="abc123"):
                pass

        cmd = mock_popen.call_args[0][0]
        self.assertIn("--agent", cmd)
        idx = cmd.index("--agent")
        self.assertEqual(cmd[idx + 1], "abc123")

    def test_exit_sends_exit_command(self) -> None:
        """__exit__ must write {"cmd":"exit"} to stdin when process is still running."""
        proc = _make_mock_proc([])

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()):
                pass

        written = "".join(
            call.args[0] for call in proc.stdin.write.call_args_list
        )
        self.assertIn('"cmd": "exit"', written)

    def test_exit_kills_on_timeout(self) -> None:
        """__exit__ must kill the process when wait() times out."""
        import subprocess as sp

        proc = _make_mock_proc([])
        proc.wait.side_effect = [sp.TimeoutExpired("red-cell-cli", 5), 0]

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()):
                pass

        proc.kill.assert_called_once()

    def test_exit_skips_exit_cmd_when_process_dead(self) -> None:
        """__exit__ must not write to stdin if the process has already exited."""
        proc = _make_mock_proc([])
        proc.poll.return_value = 0  # already exited

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()):
                pass

        # No write should have been attempted
        proc.stdin.write.assert_not_called()


# ── Session.send ──────────────────────────────────────────────────────────────

class TestSessionSend(unittest.TestCase):
    def test_send_ping_returns_pong(self) -> None:
        """send() must return the data dict for a successful ping."""
        proc = _make_mock_proc([_ok_envelope("ping", {"pong": True})])

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                result = sess.send({"cmd": "ping"})

        self.assertEqual(result, {"pong": True})

    def test_send_writes_json_line(self) -> None:
        """send() must write the command as a JSON line with trailing newline."""
        proc = _make_mock_proc([_ok_envelope("ping", {"pong": True})])

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                sess.send({"cmd": "ping"})

        # First write call (before __exit__) should be the ping
        first_write = proc.stdin.write.call_args_list[0].args[0]
        parsed = json.loads(first_write.rstrip("\n"))
        self.assertEqual(parsed["cmd"], "ping")
        self.assertTrue(first_write.endswith("\n"))

    def test_send_raises_session_error_on_error_envelope(self) -> None:
        """send() must raise SessionError when ok=false and raise_on_error=True."""
        proc = _make_mock_proc([
            _err_envelope("agent.exec", "NOT_FOUND", "agent not found"),
        ])

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                with self.assertRaises(SessionError) as cm:
                    sess.send({"cmd": "agent.exec", "id": "bad-id", "command": "ls"})

        self.assertEqual(cm.exception.code, "NOT_FOUND")
        self.assertIn("agent not found", cm.exception.message)

    def test_send_returns_envelope_when_raise_on_error_false(self) -> None:
        """send(raise_on_error=False) must return the raw envelope on error."""
        proc = _make_mock_proc([
            _err_envelope("agent.exec", "NOT_FOUND", "agent not found"),
        ])

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                raw = sess.send(
                    {"cmd": "agent.exec", "id": "bad", "command": "ls"},
                    raise_on_error=False,
                )

        self.assertFalse(raw.get("ok"))
        self.assertEqual(raw.get("error"), "NOT_FOUND")

    def test_send_raises_session_error_on_eof(self) -> None:
        """send() must raise SessionError with code 'EOF' when stdout is closed."""
        proc = _make_mock_proc([])  # no lines — readline returns ""

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                with self.assertRaises(SessionError) as cm:
                    sess.send({"cmd": "ping"})

        self.assertEqual(cm.exception.code, "EOF")

    def test_send_raises_eof_on_split_sentinel(self) -> None:
        """Regression for split-EOF accumulation across _readline calls.

        Before the fix (eofs_seen was a local variable), the first None sentinel
        consumed during send #1 was silently discarded. send #2 would then see only
        one None and block until timeout, raising TIMEOUT instead of EOF.

        The fix promotes eofs_seen to an instance variable so the count persists
        across calls, allowing send #2 to detect the second sentinel and raise EOF.
        """
        done = threading.Event()

        proc = MagicMock()
        proc.poll.return_value = None
        proc.wait.return_value = 0
        proc.stdin = MagicMock()
        proc.stdin.__enter__ = lambda s: s
        proc.stdin.__exit__ = MagicMock(return_value=False)
        proc.stdout = MagicMock()
        # Reader threads block so they contribute no queue items of their own.
        proc.stdout.readline.side_effect = lambda: (done.wait(), "")[1]
        proc.stderr = MagicMock()
        proc.stderr.readline.side_effect = lambda: (done.wait(), "")[1]

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                # Inject: first EOF sentinel before the response (simulates one
                # reader closing just before the response arrives), then the
                # response, then the second EOF sentinel.
                sess._lines.put(None)
                sess._lines.put(_ok_envelope("ping", {"pong": True}))
                sess._lines.put(None)

                r1 = sess.send({"cmd": "ping"})

                with self.assertRaises(SessionError) as cm:
                    sess.send({"cmd": "ping"})

            done.set()  # unblock daemon reader threads for clean teardown

        self.assertTrue(r1.get("pong"))
        self.assertEqual(cm.exception.code, "EOF")

    def test_send_raises_session_error_on_non_json(self) -> None:
        """send() must raise SessionError with code 'PARSE_ERROR' for non-JSON."""
        proc = _make_mock_proc(["not-json\n"])

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                with self.assertRaises(SessionError) as cm:
                    sess.send({"cmd": "ping"})

        self.assertEqual(cm.exception.code, "PARSE_ERROR")

    def test_send_agent_list_returns_list(self) -> None:
        """send() for agent.list must return a list."""
        agents = [{"id": "abc", "hostname": "host1"}, {"id": "def", "hostname": "host2"}]
        proc = _make_mock_proc([_ok_envelope("agent.list", agents)])

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                result = sess.send({"cmd": "agent.list"})

        self.assertEqual(result, agents)

    def test_multiple_sequential_sends(self) -> None:
        """Multiple send() calls on the same session must work in sequence."""
        proc = _make_mock_proc([
            _ok_envelope("ping", {"pong": True}),
            _ok_envelope("agent.list", []),
            _ok_envelope("ping", {"pong": True}),
        ])

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                r1 = sess.send({"cmd": "ping"})
                r2 = sess.send({"cmd": "agent.list"})
                r3 = sess.send({"cmd": "ping"})

        self.assertTrue(r1.get("pong"))
        self.assertEqual(r2, [])
        self.assertTrue(r3.get("pong"))

    def test_send_without_context_manager_raises(self) -> None:
        """send() must raise AssertionError when called outside a with block."""
        sess = Session(_cfg())
        with self.assertRaises(AssertionError):
            sess.send({"cmd": "ping"})


# ── Session.send_batch ────────────────────────────────────────────────────────

class TestSessionSendBatch(unittest.TestCase):
    def test_batch_returns_responses_in_order(self) -> None:
        """send_batch() must return one envelope per command, in order."""
        proc = _make_mock_proc([
            _ok_envelope("ping", {"pong": True}),
            _ok_envelope("agent.list", []),
            _ok_envelope("ping", {"pong": True}),
        ])

        cmds = [
            {"cmd": "ping"},
            {"cmd": "agent.list"},
            {"cmd": "ping"},
        ]

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                responses = sess.send_batch(cmds)

        self.assertEqual(len(responses), 3)
        self.assertEqual(responses[0]["cmd"], "ping")
        self.assertEqual(responses[1]["cmd"], "agent.list")
        self.assertEqual(responses[2]["cmd"], "ping")

    def test_batch_writes_all_commands(self) -> None:
        """send_batch() must write all commands to stdin and return all responses."""
        proc = _make_mock_proc([
            _ok_envelope("ping", {"pong": True}),
            _ok_envelope("ping", {"pong": True}),
        ])

        write_calls: list[str] = []

        def tracking_write(line):
            write_calls.append(line)

        proc.stdin.write.side_effect = tracking_write

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                responses = sess.send_batch([{"cmd": "ping"}, {"cmd": "ping"}])

        # Both commands were written (plus the __exit__ "exit" command)
        cmd_writes = [w for w in write_calls if '"cmd"' in w and '"exit"' not in w]
        self.assertEqual(len(cmd_writes), 2, "both commands must be written to stdin")
        # Both responses returned
        self.assertEqual(len(responses), 2)
        self.assertTrue(responses[0]["ok"])
        self.assertTrue(responses[1]["ok"])

    def test_batch_raises_on_early_eof(self) -> None:
        """send_batch() must raise SessionError when stdout closes early."""
        proc = _make_mock_proc([
            _ok_envelope("ping", {"pong": True}),
            # Missing second response — readline returns ""
        ])

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                with self.assertRaises(SessionError) as cm:
                    sess.send_batch([{"cmd": "ping"}, {"cmd": "ping"}])

        self.assertEqual(cm.exception.code, "EOF")

    def test_batch_includes_error_envelopes(self) -> None:
        """send_batch() must return error envelopes without raising."""
        proc = _make_mock_proc([
            _ok_envelope("ping", {"pong": True}),
            _err_envelope("agent.exec", "NOT_FOUND", "not found"),
        ])

        with patch("subprocess.Popen", return_value=proc):
            with Session(_cfg()) as sess:
                responses = sess.send_batch([
                    {"cmd": "ping"},
                    {"cmd": "agent.exec", "id": "x", "command": "ls"},
                ])

        self.assertTrue(responses[0]["ok"])
        self.assertFalse(responses[1]["ok"])
        self.assertEqual(responses[1]["error"], "NOT_FOUND")


# ── Session.close_stdin ───────────────────────────────────────────────────────

class TestSessionCloseStdin(unittest.TestCase):
    def test_close_stdin_closes_pipe(self) -> None:
        """close_stdin() must call stdin.close() when process is running."""
        proc = _make_mock_proc([_ok_envelope("ping", {"pong": True})])

        with patch("subprocess.Popen", return_value=proc):
            sess = Session(_cfg())
            sess.__enter__()
            sess.send({"cmd": "ping"})
            sess.close_stdin()
            # Prevent __exit__ from trying to write again
            proc.poll.return_value = 0
            sess.__exit__(None, None, None)

        proc.stdin.close.assert_called()

    def test_close_stdin_noop_when_already_exited(self) -> None:
        """close_stdin() must not raise when the process has already exited."""
        proc = _make_mock_proc([])
        proc.poll.return_value = 0

        with patch("subprocess.Popen", return_value=proc):
            sess = Session(_cfg())
            sess.__enter__()
            # Process is already dead
            sess.close_stdin()
            sess.__exit__(None, None, None)

        # Should not have called close (process was already dead)
        proc.stdin.close.assert_not_called()


# ── Session.wait ─────────────────────────────────────────────────────────────

class TestSessionWait(unittest.TestCase):
    def test_wait_returns_exit_code(self) -> None:
        """wait() must return the process exit code."""
        proc = _make_mock_proc([])
        proc.wait.return_value = 0

        with patch("subprocess.Popen", return_value=proc):
            sess = Session(_cfg())
            sess.__enter__()
            code = sess.wait(timeout=1)
            proc.poll.return_value = 0
            sess.__exit__(None, None, None)

        self.assertEqual(code, 0)

    def test_wait_kills_on_timeout(self) -> None:
        """wait() must kill the process when it times out."""
        import subprocess as sp

        proc = _make_mock_proc([])
        # wait() is called twice inside Session.wait() (raise then return after
        # kill), plus once more by __exit__ → provide three return values.
        proc.wait.side_effect = [sp.TimeoutExpired("red-cell-cli", 1), 137, 137]

        with patch("subprocess.Popen", return_value=proc):
            sess = Session(_cfg())
            sess.__enter__()
            sess.wait(timeout=1)
            # Mark as already exited so __exit__ still calls wait() but skip
            # the stdin-write branch.
            proc.poll.return_value = 137
            sess.__exit__(None, None, None)

        proc.kill.assert_called()


if __name__ == "__main__":
    unittest.main()
