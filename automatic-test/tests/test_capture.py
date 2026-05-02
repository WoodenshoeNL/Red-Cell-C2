"""Unit tests for lib/capture.py — wire-corpus capture infrastructure."""

from __future__ import annotations

import hashlib
import http.server
import json
import threading
import unittest
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.capture import (
    CORPUS_FORMAT_VERSION,
    CapturingSession,
    CorpusCapture,
    CorpusCapturePatch,
    _BufferedHTTPResponse,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── CorpusCapture tests ───────────────────────────────────────────────────────

class TestCorpusCapture(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.corpus_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_directory_created_on_init(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "phantom", "04")
        self.assertTrue(cap.output_dir.is_dir())
        self.assertEqual(cap.output_dir, self.corpus_dir / "phantom" / "04")

    def test_invalid_agent_type_raises(self) -> None:
        with self.assertRaises(ValueError):
            CorpusCapture(self.corpus_dir, "unknown_agent", "04")

    def test_all_valid_agent_types_accepted(self) -> None:
        for agent_type in ("demon", "archon", "phantom", "specter"):
            with self.subTest(agent_type=agent_type):
                cap = CorpusCapture(self.corpus_dir, agent_type, "test")
                self.assertEqual(cap.agent_type, agent_type)

    def test_record_packet_writes_bin_and_meta(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "phantom", "04")
        raw = b"hello corpus"
        seq = cap.record_packet("tx", raw)

        self.assertEqual(seq, 0)
        bin_path = cap.output_dir / "0000.bin"
        meta_path = cap.output_dir / "0000.meta.json"
        self.assertTrue(bin_path.exists())
        self.assertTrue(meta_path.exists())
        self.assertEqual(bin_path.read_bytes(), raw)

    def test_meta_json_schema_matches_corpus_packet_meta(self) -> None:
        """Meta sidecar must match CorpusPacketMeta from common/src/corpus.rs."""
        cap = CorpusCapture(self.corpus_dir, "demon", "13")
        raw = b"\xde\xad\xbe\xef" * 8
        cap.record_packet("rx", raw, expected_handler="DEMON_CHECKIN")

        meta = json.loads((cap.output_dir / "0000.meta.json").read_text())

        self.assertEqual(meta["version"], CORPUS_FORMAT_VERSION)
        self.assertEqual(meta["seq"], 0)
        self.assertEqual(meta["direction"], "rx")
        self.assertEqual(meta["agent_type"], "demon")
        self.assertEqual(meta["scenario"], "13")
        self.assertIsInstance(meta["captured_at_unix"], int)
        self.assertEqual(meta["bytes_sha256"], _sha256(raw))
        self.assertEqual(meta["byte_len"], len(raw))
        self.assertEqual(meta["expected_handler"], "DEMON_CHECKIN")

    def test_meta_expected_handler_none(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "phantom", "04")
        cap.record_packet("tx", b"x")
        meta = json.loads((cap.output_dir / "0000.meta.json").read_text())
        self.assertIsNone(meta["expected_handler"])

    def test_seq_increments_monotonically(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "specter", "07")
        for expected in range(5):
            seq = cap.record_packet("tx", b"pkt")
            self.assertEqual(seq, expected)

    def test_packet_count_returns_seq(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "archon", "01")
        self.assertEqual(cap.packet_count(), 0)
        cap.record_packet("tx", b"a")
        cap.record_packet("rx", b"b")
        self.assertEqual(cap.packet_count(), 2)

    def test_invalid_direction_raises(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "phantom", "04")
        with self.assertRaises(ValueError):
            cap.record_packet("invalid", b"x")

    def test_zero_byte_packet_writes_correctly(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "demon", "13")
        cap.record_packet("rx", b"")
        meta = json.loads((cap.output_dir / "0000.meta.json").read_text())
        self.assertEqual(meta["byte_len"], 0)
        self.assertEqual(meta["bytes_sha256"], _sha256(b""))

    def test_sequential_filenames_zero_padded(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "phantom", "04")
        for _ in range(12):
            cap.record_packet("tx", b"x")
        # Tenth packet should be 0009.bin, twelfth should be 0011.bin
        self.assertTrue((cap.output_dir / "0009.bin").exists())
        self.assertTrue((cap.output_dir / "0011.bin").exists())

    # ── session keys ─────────────────────────────────────────────────────────

    def test_write_session_keys_null_stub(self) -> None:
        """Null-field stub is the expected output before red-cell-c2-00hf1 lands."""
        cap = CorpusCapture(self.corpus_dir, "phantom", "04")
        path = cap.write_session_keys()

        self.assertTrue(path.exists())
        self.assertEqual(path.name, "session.keys.json")

        keys = json.loads(path.read_text())
        self.assertEqual(keys["version"], CORPUS_FORMAT_VERSION)
        self.assertIsNone(keys["aes_key_hex"])
        self.assertIsNone(keys["aes_iv_hex"])
        self.assertIsNone(keys["monotonic_ctr"])
        self.assertIsNone(keys["initial_ctr_block_offset"])
        self.assertIsNone(keys["agent_id_hex"])

    def test_write_session_keys_populated(self) -> None:
        """When key material is available (post-red-cell-c2-00hf1), fields are non-null."""
        cap = CorpusCapture(self.corpus_dir, "demon", "13")
        cap.write_session_keys(
            aes_key_hex="a" * 64,
            aes_iv_hex="b" * 32,
            monotonic_ctr=False,
            initial_ctr_block_offset=0,
            agent_id_hex="0x12345678",
        )
        keys = json.loads((cap.output_dir / "session.keys.json").read_text())
        self.assertEqual(keys["version"], CORPUS_FORMAT_VERSION)
        self.assertEqual(keys["aes_key_hex"], "a" * 64)
        self.assertEqual(keys["aes_iv_hex"], "b" * 32)
        self.assertFalse(keys["monotonic_ctr"])
        self.assertEqual(keys["initial_ctr_block_offset"], 0)
        self.assertEqual(keys["agent_id_hex"], "0x12345678")

    def test_session_keys_schema_matches_corpus_session_keys(self) -> None:
        """Field names must match CorpusSessionKeys in common/src/corpus.rs."""
        cap = CorpusCapture(self.corpus_dir, "archon", "02")
        cap.write_session_keys(
            aes_key_hex="c" * 64,
            aes_iv_hex="d" * 32,
            monotonic_ctr=True,
            initial_ctr_block_offset=42,
            agent_id_hex="0xDEADBEEF",
        )
        keys = json.loads((cap.output_dir / "session.keys.json").read_text())
        required_fields = {
            "version", "aes_key_hex", "aes_iv_hex",
            "monotonic_ctr", "initial_ctr_block_offset", "agent_id_hex",
        }
        self.assertEqual(set(keys.keys()), required_fields)
        self.assertTrue(keys["monotonic_ctr"])
        self.assertEqual(keys["initial_ctr_block_offset"], 42)

    def test_scenario_directory_layout(self) -> None:
        """Verify the on-disk layout matches the corpus format spec."""
        cap = CorpusCapture(self.corpus_dir, "phantom", "04")
        cap.record_packet("tx", b"req")
        cap.record_packet("rx", b"resp")
        cap.write_session_keys()

        expected = [
            self.corpus_dir / "phantom" / "04" / "0000.bin",
            self.corpus_dir / "phantom" / "04" / "0000.meta.json",
            self.corpus_dir / "phantom" / "04" / "0001.bin",
            self.corpus_dir / "phantom" / "04" / "0001.meta.json",
            self.corpus_dir / "phantom" / "04" / "session.keys.json",
        ]
        for p in expected:
            with self.subTest(file=p.name):
                self.assertTrue(p.exists(), f"expected {p} to exist")


# ── _BufferedHTTPResponse tests ───────────────────────────────────────────────

class TestBufferedHTTPResponse(unittest.TestCase):

    def _make(self, body: bytes) -> _BufferedHTTPResponse:
        class _FakeReal:
            status = 200
            headers: dict = {}
            def close(self) -> None: pass
        return _BufferedHTTPResponse(_FakeReal(), body)

    def test_read_all(self) -> None:
        resp = self._make(b"hello")
        self.assertEqual(resp.read(), b"hello")

    def test_read_partial(self) -> None:
        resp = self._make(b"hello")
        self.assertEqual(resp.read(3), b"hel")
        self.assertEqual(resp.read(2), b"lo")
        self.assertEqual(resp.read(), b"")

    def test_readline(self) -> None:
        resp = self._make(b"line1\nline2\n")
        self.assertEqual(resp.readline(), b"line1\n")
        self.assertEqual(resp.readline(), b"line2\n")
        self.assertEqual(resp.readline(), b"")

    def test_context_manager(self) -> None:
        resp = self._make(b"data")
        with resp as r:
            self.assertEqual(r.read(), b"data")

    def test_delegates_status(self) -> None:
        resp = self._make(b"")
        self.assertEqual(resp.status, 200)


# ── CorpusCapturePatch tests ──────────────────────────────────────────────────

class _EchoHandler(http.server.BaseHTTPRequestHandler):
    """Test HTTP server: echoes POST body; returns b"get-response" for GET."""

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        body = b"get-response"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PATCH(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: object) -> None:
        pass  # suppress test output


class TestCorpusCapturePatch(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._server = http.server.HTTPServer(("127.0.0.1", 0), _EchoHandler)
        cls._port = cls._server.server_address[1]
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._server.shutdown()

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.corpus_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _url(self) -> str:
        return f"http://127.0.0.1:{self._port}/demon"

    def test_patch_captures_rx_then_tx(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "demon", "13")
        payload = b"\xde\xad\xbe\xef" * 4

        with CorpusCapturePatch(cap):
            req = urllib.request.Request(self._url(), data=payload, method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read()

        self.assertEqual(body, payload)  # caller still sees response

        self.assertTrue((cap.output_dir / "0000.bin").exists())  # RX (agent request)
        self.assertTrue((cap.output_dir / "0001.bin").exists())  # TX (teamserver response)
        self.assertEqual((cap.output_dir / "0000.bin").read_bytes(), payload)
        self.assertEqual((cap.output_dir / "0001.bin").read_bytes(), payload)

    def test_patch_meta_direction_correct(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "demon", "13")
        with CorpusCapturePatch(cap):
            req = urllib.request.Request(self._url(), data=b"abc", method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()

        # 0000 = agent request body, received by teamserver → "rx"
        # 0001 = teamserver response body, transmitted by teamserver → "tx"
        req_meta = json.loads((cap.output_dir / "0000.meta.json").read_text())
        resp_meta = json.loads((cap.output_dir / "0001.meta.json").read_text())
        self.assertEqual(req_meta["direction"], "rx")
        self.assertEqual(resp_meta["direction"], "tx")

    def test_patch_restores_urlopen_after_exit(self) -> None:
        original = urllib.request.urlopen
        cap = CorpusCapture(self.corpus_dir, "demon", "13")
        with CorpusCapturePatch(cap):
            patched = urllib.request.urlopen
            self.assertIsNot(patched, original)
        self.assertIs(urllib.request.urlopen, original)

    def test_patch_restores_on_exception(self) -> None:
        original = urllib.request.urlopen
        cap = CorpusCapture(self.corpus_dir, "phantom", "04")
        try:
            with CorpusCapturePatch(cap):
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        self.assertIs(urllib.request.urlopen, original)

    def test_patch_body_readable_after_capture(self) -> None:
        """The caller must still be able to read the full response body."""
        cap = CorpusCapture(self.corpus_dir, "specter", "07")
        data = b"x" * 512
        with CorpusCapturePatch(cap):
            req = urllib.request.Request(self._url(), data=data, method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read()
        self.assertEqual(len(body), 512)

    def test_patch_records_empty_request_body(self) -> None:
        """Empty request body must still produce an RX packet (seq 0)."""
        cap = CorpusCapture(self.corpus_dir, "demon", "14")
        with CorpusCapturePatch(cap):
            req = urllib.request.Request(self._url(), data=b"", method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
        # Both RX (empty request) and TX (empty echo response) must be recorded.
        self.assertEqual(cap.packet_count(), 2)
        self.assertEqual((cap.output_dir / "0000.bin").read_bytes(), b"")
        self.assertEqual((cap.output_dir / "0001.bin").read_bytes(), b"")

    def test_patch_empty_body_seq_consistent_with_capturing_session(self) -> None:
        """CorpusCapturePatch and CapturingSession must assign identical seq numbers
        for empty-body exchanges on the same CorpusCapture instance."""
        cap_patch = CorpusCapture(self.corpus_dir / "patch", "demon", "15")
        cap_session = CorpusCapture(self.corpus_dir / "session", "demon", "15")

        # Route an empty-body POST through CorpusCapturePatch.
        with CorpusCapturePatch(cap_patch):
            req = urllib.request.Request(self._url(), data=b"", method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()

        # Route the same empty-body POST through CapturingSession.
        session = CapturingSession(cap_session, timeout=5)
        session.post(self._url(), data=b"")

        # Both must produce exactly 2 packets with the same seq numbers.
        self.assertEqual(cap_patch.packet_count(), 2)
        self.assertEqual(cap_session.packet_count(), 2)

        patch_rx_meta = json.loads((cap_patch.output_dir / "0000.meta.json").read_text())
        patch_tx_meta = json.loads((cap_patch.output_dir / "0001.meta.json").read_text())
        sess_rx_meta = json.loads((cap_session.output_dir / "0000.meta.json").read_text())
        sess_tx_meta = json.loads((cap_session.output_dir / "0001.meta.json").read_text())

        self.assertEqual(patch_rx_meta["seq"], sess_rx_meta["seq"])
        self.assertEqual(patch_tx_meta["seq"], sess_tx_meta["seq"])
        self.assertEqual(patch_rx_meta["direction"], sess_rx_meta["direction"])
        self.assertEqual(patch_tx_meta["direction"], sess_tx_meta["direction"])

    def test_patch_get_produces_one_tx_packet(self) -> None:
        """GET through CorpusCapturePatch must record exactly 1 packet (TX only),
        matching CapturingSession.get behaviour — no spurious empty RX packet."""
        cap = CorpusCapture(self.corpus_dir, "demon", "16")
        with CorpusCapturePatch(cap):
            req = urllib.request.Request(self._url(), method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()

        self.assertEqual(cap.packet_count(), 1)
        meta = json.loads((cap.output_dir / "0000.meta.json").read_text())
        self.assertEqual(meta["direction"], "tx")

    def test_put_request_with_body_records_rx(self) -> None:
        """PUT request with a body must record an RX packet — not be silently dropped."""
        cap = CorpusCapture(self.corpus_dir, "demon", "17")
        payload = b"put-body-data"
        with CorpusCapturePatch(cap):
            req = urllib.request.Request(self._url(), data=payload, method="PUT")
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()

        self.assertEqual(cap.packet_count(), 2)
        rx_meta = json.loads((cap.output_dir / "0000.meta.json").read_text())
        self.assertEqual(rx_meta["direction"], "rx")
        self.assertEqual((cap.output_dir / "0000.bin").read_bytes(), payload)

    def test_patch_request_with_body_records_rx(self) -> None:
        """PATCH request with a body must record an RX packet — not be silently dropped."""
        cap = CorpusCapture(self.corpus_dir, "demon", "18")
        payload = b"patch-body-data"
        with CorpusCapturePatch(cap):
            req = urllib.request.Request(self._url(), data=payload, method="PATCH")
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()

        self.assertEqual(cap.packet_count(), 2)
        rx_meta = json.loads((cap.output_dir / "0000.meta.json").read_text())
        self.assertEqual(rx_meta["direction"], "rx")
        self.assertEqual((cap.output_dir / "0000.bin").read_bytes(), payload)


# ── CapturingSession tests ────────────────────────────────────────────────────

class TestCapturingSession(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._server = http.server.HTTPServer(("127.0.0.1", 0), _EchoHandler)
        cls._port = cls._server.server_address[1]
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._server.shutdown()

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.corpus_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _url(self) -> str:
        return f"http://127.0.0.1:{self._port}/demon"

    def test_post_returns_status_and_body(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "demon", "13")
        session = CapturingSession(cap, timeout=5)
        payload = b"demon-packet"
        status, body = session.post(self._url(), data=payload)
        self.assertEqual(status, 200)
        self.assertEqual(body, payload)

    def test_post_writes_rx_then_tx(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "demon", "13")
        session = CapturingSession(cap, timeout=5)
        session.post(self._url(), data=b"pkt", expected_handler="DEMON_CHECKIN")

        self.assertEqual(cap.packet_count(), 2)
        # 0000 = agent request body, received by teamserver → direction "rx"
        # 0001 = teamserver response body, transmitted by teamserver → direction "tx"
        req_meta = json.loads((cap.output_dir / "0000.meta.json").read_text())
        resp_meta = json.loads((cap.output_dir / "0001.meta.json").read_text())
        self.assertEqual(req_meta["direction"], "rx")
        self.assertEqual(req_meta["expected_handler"], "DEMON_CHECKIN")
        self.assertEqual(resp_meta["direction"], "tx")
        self.assertIsNone(resp_meta["expected_handler"])

    def test_meta_bytes_sha256_correct(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "phantom", "04")
        session = CapturingSession(cap, timeout=5)
        raw = b"sha256-check"
        session.post(self._url(), data=raw)

        req_meta = json.loads((cap.output_dir / "0000.meta.json").read_text())
        self.assertEqual(req_meta["bytes_sha256"], _sha256(raw))

    def test_get_returns_status_and_body(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "demon", "14")
        session = CapturingSession(cap, timeout=5)
        status, body = session.get(self._url())
        self.assertEqual(status, 200)
        self.assertEqual(body, b"get-response")

    def test_get_writes_tx_meta(self) -> None:
        cap = CorpusCapture(self.corpus_dir, "demon", "15")
        session = CapturingSession(cap, timeout=5)
        session.get(self._url())

        # GET records only the response — one packet total
        self.assertEqual(cap.packet_count(), 1)
        meta = json.loads((cap.output_dir / "0000.meta.json").read_text())
        # Response from teamserver → agent is "tx" (transmitted by teamserver)
        self.assertEqual(meta["direction"], "tx")

    def test_get_http_error_captured_as_tx(self) -> None:
        # Spin up a dedicated 404 server to exercise the HTTPError branch.
        class _404Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                msg = b"not found"
                self.send_response(404)
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)

            def log_message(self, *_: object) -> None:
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), _404Handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            cap = CorpusCapture(self.corpus_dir, "demon", "16")
            session = CapturingSession(cap, timeout=5)
            status, body = session.get(f"http://127.0.0.1:{port}/")
            self.assertEqual(status, 404)
            self.assertEqual(body, b"not found")
            # HTTPError response is still captured as TX
            self.assertEqual(cap.packet_count(), 1)
            meta = json.loads((cap.output_dir / "0000.meta.json").read_text())
            self.assertEqual(meta["direction"], "tx")
        finally:
            srv.shutdown()
            srv.server_close()


# ── Format-version constant tests ────────────────────────────────────────────

class TestFormatVersion(unittest.TestCase):

    def test_corpus_format_version_is_one(self) -> None:
        self.assertEqual(CORPUS_FORMAT_VERSION, 1)

    def test_meta_version_field_equals_constant(self) -> None:
        with TemporaryDirectory() as tmp:
            cap = CorpusCapture(Path(tmp), "phantom", "04")
            cap.record_packet("tx", b"v")
            meta = json.loads((cap.output_dir / "0000.meta.json").read_text())
            self.assertEqual(meta["version"], CORPUS_FORMAT_VERSION)

    def test_session_keys_version_field_equals_constant(self) -> None:
        with TemporaryDirectory() as tmp:
            cap = CorpusCapture(Path(tmp), "phantom", "04")
            cap.write_session_keys()
            keys = json.loads((cap.output_dir / "session.keys.json").read_text())
            self.assertEqual(keys["version"], CORPUS_FORMAT_VERSION)


if __name__ == "__main__":
    unittest.main()
