"""
lib/capture.py — wire-corpus capture for protocol conformance testing.

Intercepts HTTP TX/RX at the Python layer and writes corpus files in the
CorpusPacketMeta / CorpusSessionKeys format defined in common/src/corpus.rs.

On-disk layout (mirrors the Rust corpus format):

    <corpus_dir>/
      <agent_type>/          e.g. "demon", "archon", "phantom", "specter"
        <scenario_id>/       e.g. "04", "13", "checkin"
          0000.bin           raw on-wire bytes (TX = agent→teamserver)
          0000.meta.json     metadata sidecar (see CorpusPacketMeta in corpus.rs)
          0001.bin           raw bytes (RX = teamserver→agent)
          0001.meta.json
          ...
          session.keys.json  CorpusSessionKeys — null until teamserver middleware lands

Usage (explicit capture via CapturingSession):

    capture = CorpusCapture(corpus_dir, agent_type="phantom", scenario_id="04")
    session = CapturingSession(capture)
    status, body = session.post("http://teamserver:19081/demon", data=raw_bytes)
    capture.write_session_keys()   # writes null stub until red-cell-c2-00hf1 lands

Usage (automatic monkeypatching of urllib):

    capture = CorpusCapture(corpus_dir, agent_type="demon", scenario_id="13")
    with CorpusCapturePatch(capture):
        urllib.request.urlopen(req)   # automatically captured
    capture.write_session_keys()
"""

from __future__ import annotations

import hashlib
import http.client
import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

#: Format version written into every meta sidecar.  Must match CORPUS_FORMAT_VERSION in
#: common/src/corpus.rs.  Bump both if the sidecar JSON schema changes incompatibly.
CORPUS_FORMAT_VERSION: int = 1

_VALID_AGENT_TYPES = frozenset({"demon", "archon", "phantom", "specter"})
_VALID_DIRECTIONS = frozenset({"tx", "rx"})


class CorpusCapture:
    """Manages corpus file writing for one scenario execution.

    Thread-safe: ``record_packet`` may be called concurrently from multiple
    threads (e.g. during parallel build passes in the test harness).

    Args:
        corpus_dir: Root corpus directory (the value of ``--capture-corpus``).
        agent_type: Agent type string — one of ``"demon"``, ``"archon"``,
                    ``"phantom"``, ``"specter"``.
        scenario_id: Scenario identifier used as the inner directory name
                     (e.g. ``"04"``, ``"13"``).
    """

    def __init__(self, corpus_dir: Path, agent_type: str, scenario_id: str) -> None:
        if agent_type not in _VALID_AGENT_TYPES:
            raise ValueError(
                f"agent_type must be one of {sorted(_VALID_AGENT_TYPES)}, got {agent_type!r}"
            )
        self._output_dir = corpus_dir / agent_type / scenario_id
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._agent_type = agent_type
        self._scenario_id = scenario_id
        self._seq = 0
        self._lock = threading.Lock()

    @property
    def output_dir(self) -> Path:
        """Directory where corpus files for this scenario are written."""
        return self._output_dir

    @property
    def agent_type(self) -> str:
        return self._agent_type

    @property
    def scenario_id(self) -> str:
        return self._scenario_id

    def record_packet(
        self,
        direction: str,
        raw_bytes: bytes,
        expected_handler: str | None = None,
    ) -> int:
        """Write a single captured packet to the corpus directory.

        Writes ``<seq:04d>.bin`` (raw bytes) and ``<seq:04d>.meta.json``
        (metadata sidecar matching ``CorpusPacketMeta`` in corpus.rs).

        Args:
            direction:        ``"tx"`` (agent→teamserver) or ``"rx"`` (teamserver→agent).
            raw_bytes:        Raw on-wire bytes — HTTP body after chunked-transfer
                              decoding but before any agent-layer decryption.
            expected_handler: Optional teamserver handler hint for replay tests
                              (e.g. ``"DEMON_INIT"``, ``"DEMON_CHECKIN"``).

        Returns:
            The zero-based sequence number assigned to this packet.
        """
        if direction not in _VALID_DIRECTIONS:
            raise ValueError(f"direction must be 'tx' or 'rx', got {direction!r}")

        with self._lock:
            seq = self._seq
            self._seq += 1

        sha = hashlib.sha256(raw_bytes).hexdigest()
        captured_at = int(time.time())

        bin_path = self._output_dir / f"{seq:04d}.bin"
        bin_path.write_bytes(raw_bytes)

        meta: dict[str, Any] = {
            "version": CORPUS_FORMAT_VERSION,
            "seq": seq,
            "direction": direction,
            "agent_type": self._agent_type,
            "scenario": self._scenario_id,
            "captured_at_unix": captured_at,
            "bytes_sha256": sha,
            "byte_len": len(raw_bytes),
            "expected_handler": expected_handler,
        }
        meta_path = self._output_dir / f"{seq:04d}.meta.json"
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

        return seq

    def write_session_keys(
        self,
        aes_key_hex: str | None = None,
        aes_iv_hex: str | None = None,
        monotonic_ctr: bool | None = None,
        initial_ctr_block_offset: int | None = None,
        agent_id_hex: str | None = None,
    ) -> Path:
        """Write ``session.keys.json`` with the given key material.

        All parameters default to ``None``.  Null fields are valid and expected
        until the teamserver side-channel (``red-cell-c2-00hf1``) is merged.
        The schema matches ``CorpusSessionKeys`` in ``common/src/corpus.rs``.

        Returns:
            Path to the written ``session.keys.json`` file.
        """
        keys: dict[str, Any] = {
            "version": CORPUS_FORMAT_VERSION,
            "aes_key_hex": aes_key_hex,
            "aes_iv_hex": aes_iv_hex,
            "monotonic_ctr": monotonic_ctr,
            "initial_ctr_block_offset": initial_ctr_block_offset,
            "agent_id_hex": agent_id_hex,
        }
        path = self._output_dir / "session.keys.json"
        path.write_text(json.dumps(keys, indent=2), encoding="utf-8")
        return path

    def packet_count(self) -> int:
        """Return the number of packets recorded so far."""
        with self._lock:
            return self._seq


# ── Buffered response wrapper ─────────────────────────────────────────────────

class _BufferedHTTPResponse:
    """Wraps a urllib HTTP response, buffering the body so it can be read twice.

    ``CorpusCapturePatch`` reads the entire response body eagerly to capture it,
    then stores it here so the original caller can still ``read()`` the data.
    """

    __slots__ = ("_body", "_pos", "_real")

    def __init__(self, real: Any, body: bytes) -> None:
        self._real = real
        self._body = body
        self._pos = 0

    def read(self, amt: int = -1) -> bytes:
        if amt < 0:
            chunk = self._body[self._pos:]
            self._pos = len(self._body)
        else:
            chunk = self._body[self._pos: self._pos + amt]
            self._pos += len(chunk)
        return chunk

    def readline(self) -> bytes:
        end = self._body.find(b"\n", self._pos)
        if end < 0:
            chunk = self._body[self._pos:]
            self._pos = len(self._body)
        else:
            chunk = self._body[self._pos: end + 1]
            self._pos = end + 1
        return chunk

    def __enter__(self) -> "_BufferedHTTPResponse":
        return self

    def __exit__(self, *_: Any) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


# ── Capturing session (explicit use) ─────────────────────────────────────────

class CapturingSession:
    """urllib-based HTTP session wrapper that records TX/RX into a ``CorpusCapture``.

    Use this for scenarios that want explicit, fine-grained control over which
    HTTP calls are recorded.  For automatic interception of all ``urllib`` calls,
    see ``CorpusCapturePatch``.

    Example::

        capture = CorpusCapture(corpus_dir, "phantom", "04")
        session = CapturingSession(capture, timeout=10)
        status, body = session.post(url, data=raw_bytes, expected_handler="DEMON_CHECKIN")
    """

    def __init__(self, capture: CorpusCapture, timeout: int = 10) -> None:
        self._capture = capture
        self._timeout = timeout

    def post(
        self,
        url: str,
        data: bytes,
        headers: dict[str, str] | None = None,
        expected_handler: str | None = None,
    ) -> tuple[int, bytes]:
        """POST raw bytes to ``url``, capturing the TX body and RX response.

        Args:
            url:              Target URL (e.g. ``http://teamserver:19081/demon``).
            data:             Raw request body bytes to send and capture as TX.
            headers:          Additional HTTP request headers.
            expected_handler: Forwarded to ``CorpusCapture.record_packet`` TX entry.

        Returns:
            ``(status_code, response_body)`` — 4xx/5xx responses are returned,
            not raised, so callers can assert on rejection responses too.
        """
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/octet-stream")
        for k, v in (headers or {}).items():
            req.add_header(k, v)

        self._capture.record_packet("tx", data, expected_handler=expected_handler)

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            body = exc.read()
            status = exc.code

        self._capture.record_packet("rx", body)
        return status, body

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        """GET ``url``, capturing the RX response body.

        The GET request itself has no body; only the response is recorded (as RX).

        Returns:
            ``(status_code, response_body)``.
        """
        req = urllib.request.Request(url, method="GET")
        for k, v in (headers or {}).items():
            req.add_header(k, v)

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            body = exc.read()
            status = exc.code

        self._capture.record_packet("rx", body)
        return status, body


# ── Automatic urllib monkeypatching ───────────────────────────────────────────

class CorpusCapturePatch:
    """Context manager that monkeypatches ``urllib.request.urlopen`` for passive capture.

    While active, every call to ``urllib.request.urlopen`` within the same
    process is intercepted:

    * The request body (if any) is recorded as a TX packet.
    * The response body is buffered, recorded as an RX packet, and then
      returned to the caller wrapped in ``_BufferedHTTPResponse`` so the
      caller can still ``read()`` the data normally.
    * ``urllib.error.HTTPError`` (4xx/5xx) responses are also captured before
      the exception is re-raised.

    This is intended for scenarios that use ``urllib.request`` directly (e.g.
    the protocol-compliance scenario).  Scenarios that already use
    ``CapturingSession`` do not need this patch.

    Thread safety: the monkeypatch is process-global.  Do not nest
    ``CorpusCapturePatch`` contexts or use them from multiple threads
    simultaneously.

    Example::

        capture = CorpusCapture(corpus_dir, "demon", "13")
        with CorpusCapturePatch(capture):
            req = urllib.request.Request(url, data=raw_bytes, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read()   # body is available normally
        capture.write_session_keys()
    """

    def __init__(self, capture: CorpusCapture) -> None:
        self._capture = capture
        self._orig_urlopen: Any = None

    def __enter__(self) -> "CorpusCapturePatch":
        self._orig_urlopen = urllib.request.urlopen
        capture = self._capture
        orig = self._orig_urlopen

        def _patched(req: Any, data: bytes | None = None, timeout: Any = None, **kwargs: Any) -> Any:
            tx_body: bytes = b""
            if isinstance(req, urllib.request.Request):
                tx_body = req.data or b""
            elif data is not None:
                tx_body = data

            if tx_body:
                capture.record_packet("tx", tx_body)

            call_kw: dict[str, Any] = {}
            if timeout is not None:
                call_kw["timeout"] = timeout

            try:
                resp = orig(req, data=data, **call_kw, **kwargs)
            except urllib.error.HTTPError as exc:
                rx_body = exc.read()
                if rx_body:
                    capture.record_packet("rx", rx_body)
                raise

            rx_body = resp.read()
            if rx_body:
                capture.record_packet("rx", rx_body)

            return _BufferedHTTPResponse(resp, rx_body)

        urllib.request.urlopen = _patched  # type: ignore[assignment]
        return self

    def __exit__(self, *_: Any) -> None:
        if self._orig_urlopen is not None:
            urllib.request.urlopen = self._orig_urlopen  # type: ignore[assignment]
            self._orig_urlopen = None
