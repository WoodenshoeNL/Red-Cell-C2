"""
lib/session.py — subprocess helper for ``red-cell-cli session`` mode.

Opens a ``red-cell-cli session`` subprocess and drives the persistent
newline-delimited JSON pipe protocol: write one JSON object per line to stdin,
read one JSON object per line from stdout.

Usage::

    from lib.cli import CliConfig
    from lib.session import Session, SessionError

    cfg = CliConfig(server="http://localhost:40056", token="secret")

    with Session(cfg) as sess:
        pong = sess.send({"cmd": "ping"})
        agents = sess.send({"cmd": "agent.list"})
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
from typing import Any

from .cli import CliConfig

_SENTINEL = object()


class SessionError(Exception):
    """Raised when the session process returns an error envelope or fails.

    Attributes:
        code:    The ``"error"`` field from the response envelope, or a local
                 code like ``"EOF"`` or ``"PARSE_ERROR"``.
        message: Human-readable description.
    """

    def __init__(self, code: str, message: str):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


class Session:
    """Context-manager wrapper around ``red-cell-cli session``.

    Opens a single long-lived ``red-cell-cli session`` subprocess, exposing a
    synchronous :meth:`send` method for one-shot request/response pairs and a
    :meth:`send_batch` method for pipelining multiple commands.

    The process is shut down cleanly on context-manager exit: an explicit
    ``{"cmd": "exit"}`` is sent first; if the process does not exit within 5 s
    it is killed.

    Args:
        cfg:     CLI configuration (server URL, token, binary path).
        agent:   Default agent ID injected as ``--agent`` so commands that
                 operate on an agent don't need to carry an ``"id"`` field.
        timeout: Default timeout in seconds for :meth:`send` and
                 :meth:`send_batch` readline waits.  ``None`` means block
                 forever (legacy behaviour).  Individual calls can override.
    """

    DEFAULT_TIMEOUT: float = 30.0

    def __init__(self, cfg: CliConfig, agent: str | None = None, timeout: float | None = DEFAULT_TIMEOUT):
        self._cfg = cfg
        self._agent = agent
        self._timeout = timeout
        self._proc: subprocess.Popen[str] | None = None
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._eofs_seen: int = 0

    # ── context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "Session":
        env = os.environ.copy()
        env["RC_SERVER"] = self._cfg.server
        env["RC_TOKEN"] = self._cfg.token

        fp_args = ["--cert-fingerprint", self._cfg.cert_fingerprint] if self._cfg.cert_fingerprint else []
        cmd = [self._cfg.binary, "--output", "json", *fp_args, "session"]
        if self._agent:
            cmd += ["--agent", self._agent]

        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            bufsize=1,  # line-buffered
        )
        # Drain both stdout and stderr into a shared queue so error envelopes
        # (which the CLI routes to stderr) are not missed by send().
        for stream in (self._proc.stdout, self._proc.stderr):
            t = threading.Thread(target=self._reader_thread, args=(stream,), daemon=True)
            t.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.poll() is None:
                try:
                    assert self._proc.stdin is not None
                    self._proc.stdin.write(json.dumps({"cmd": "exit"}) + "\n")
                    self._proc.stdin.flush()
                    self._proc.stdin.close()
                except OSError:
                    pass
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()

    # ── internal helpers ──────────────────────────────────────────────────────

    def _reader_thread(self, stream) -> None:
        """Read lines from *stream* and put them into the shared queue."""
        try:
            while True:
                line = stream.readline()
                if not line:
                    break
                stripped = line.strip()
                if stripped:
                    self._lines.put(stripped)
        finally:
            # Signal EOF on this stream; we put two sentinels (one per stream)
            # so the first EOF doesn't confuse send() waiting for a response.
            self._lines.put(None)

    def _readline(self, timeout: float | None = None) -> str:
        """Return the next non-empty line from either stdout or stderr.

        Raises SessionError on EOF (both streams closed).
        """
        # We have two reader threads; track how many EOF sentinels we've seen.
        # eofs_seen is an instance variable so counts accumulate across calls.
        while True:
            try:
                item = self._lines.get(timeout=timeout)
            except queue.Empty:
                raise SessionError("TIMEOUT", "timed out waiting for session response")
            if item is None:
                self._eofs_seen += 1
                if self._eofs_seen >= 2:
                    raise SessionError("EOF", "session process closed stdout/stderr unexpectedly")
                continue
            return item

    # ── public API ────────────────────────────────────────────────────────────

    def send(
        self,
        cmd: dict[str, Any],
        raise_on_error: bool = True,
        timeout: float | None = _SENTINEL,
    ) -> dict[str, Any]:
        """Send one JSON command and return the response data.

        Writes *cmd* as a single JSON line to the subprocess stdin, then reads
        one JSON line from stdout and returns the ``"data"`` field of the
        success envelope.

        Args:
            cmd:            Command dict (must include at least ``"cmd"``).
            raise_on_error: When True (default), raise :class:`SessionError` if
                            the server returns ``{"ok": false, ...}``.
            timeout:        Seconds to wait for a response.  Defaults to the
                            instance-level timeout (30 s).  Pass ``None`` to
                            block indefinitely.

        Returns:
            The ``"data"`` field of the response envelope on success, or the
            full raw envelope when *raise_on_error* is False.

        Raises:
            SessionError: On server-side error (when *raise_on_error* is True),
                          unexpected EOF, JSON parse failure, or timeout.
            AssertionError: If called outside a ``with`` block.
        """
        assert self._proc is not None, "Session not started — use as context manager"
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None

        effective_timeout = self._timeout if timeout is _SENTINEL else timeout

        self._proc.stdin.write(json.dumps(cmd) + "\n")
        self._proc.stdin.flush()

        response_line = self._readline(timeout=effective_timeout)

        try:
            envelope = json.loads(response_line)
        except json.JSONDecodeError as exc:
            raise SessionError("PARSE_ERROR", f"non-JSON response: {response_line!r}") from exc

        if raise_on_error and not envelope.get("ok", True):
            code = envelope.get("error", "UNKNOWN")
            msg = envelope.get("message", "no message")
            raise SessionError(code, msg)

        return envelope.get("data", envelope)

    def send_batch(
        self,
        cmds: list[dict[str, Any]],
        timeout: float | None = _SENTINEL,
    ) -> list[dict[str, Any]]:
        """Pipeline multiple commands without waiting between sends.

        Writes all commands to stdin before reading any responses.  Useful for
        verifying that the session handles back-to-back requests correctly.

        Returns raw response envelopes (does not raise on individual errors).

        Args:
            timeout: Per-response readline timeout.  Defaults to the
                     instance-level timeout.  Pass ``None`` to block forever.

        Raises:
            SessionError: On unexpected EOF or timeout before all responses are
                          received.
            AssertionError: If called outside a ``with`` block.
        """
        assert self._proc is not None, "Session not started — use as context manager"
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None

        effective_timeout = self._timeout if timeout is _SENTINEL else timeout

        for cmd in cmds:
            self._proc.stdin.write(json.dumps(cmd) + "\n")
        self._proc.stdin.flush()

        responses: list[dict[str, Any]] = []
        for _ in cmds:
            line = self._readline(timeout=effective_timeout)
            responses.append(json.loads(line))
        return responses

    def close_stdin(self) -> None:
        """Close stdin to send EOF without an explicit ``exit`` command.

        The session process should exit cleanly on EOF.  Call :meth:`wait`
        afterward if you need to verify the exit code.
        """
        if self._proc is not None and self._proc.poll() is None:
            try:
                assert self._proc.stdin is not None
                self._proc.stdin.close()
            except OSError:
                pass

    def wait(self, timeout: float = 5.0) -> int:
        """Wait for the session process to exit and return its exit code."""
        assert self._proc is not None
        try:
            return self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            return self._proc.wait()
