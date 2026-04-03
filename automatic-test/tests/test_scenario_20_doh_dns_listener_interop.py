"""
Unit tests for scenario 20 (DoH DNS listener interop).
"""

from __future__ import annotations

import importlib.util as _ilu
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib import ScenarioSkipped

_SCENARIO_PATH = (
    Path(__file__).parent.parent / "scenarios" / "20_agent_doh_dns_listener_interop.py"
)
_spec = _ilu.spec_from_file_location("scenario_20_doh_dns_listener_interop", _SCENARIO_PATH)
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def _make_ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.cli = MagicMock()
    ctx.env = {"listeners": {"dns_port": 15353, "dns_domain": "c2.test.local"}}
    ctx.dry_run = False
    return ctx


class TestDohNameBuilders(unittest.TestCase):
    def test_build_uplink_name_matches_agent_format(self) -> None:
        name = _mod._build_uplink_name("abcdef", 2, 15, "0011223344556677", "c2.example.com")
        self.assertEqual(name, "abcdef.0002000f.0011223344556677.u.c2.example.com")

    def test_build_ready_name_matches_agent_format(self) -> None:
        name = _mod._build_ready_name("0011223344556677", "c2.example.com")
        self.assertEqual(name, "rdy.0011223344556677.d.c2.example.com")

    def test_build_chunk_fetch_name_matches_agent_format(self) -> None:
        name = _mod._build_chunk_fetch_name(3, "0011223344556677", "c2.example.com")
        self.assertEqual(name, "0003.0011223344556677.d.c2.example.com")

    def test_chunk_packet_uses_37_byte_boundaries(self) -> None:
        packet = b"A" * 38
        chunks = _mod._chunk_packet(packet)
        self.assertEqual(len(chunks), 2)
        self.assertLessEqual(len(chunks[0]), 60)
        self.assertLessEqual(len(chunks[1]), 60)

    def test_base32_round_trip(self) -> None:
        data = b"hello world"
        encoded = _mod._encode_b32(data)
        decoded = _mod._decode_b32(encoded)
        self.assertEqual(decoded, data)


class TestDnsResponseParsing(unittest.TestCase):
    def test_parse_first_txt_answer_returns_text(self) -> None:
        qname = "rdy.0011223344556677.d.c2.example.com"
        query = _mod._build_dns_txt_query(0x1234, qname)

        response = bytearray()
        response.extend(query[:2])
        response.extend(b"\x84\x00")  # QR + AA + NOERROR
        response.extend(b"\x00\x01\x00\x01\x00\x00\x00\x00")
        response.extend(query[12:])
        response.extend(b"\xc0\x0c")
        response.extend(b"\x00\x10\x00\x01")
        response.extend(b"\x00\x00\x00\x00")
        response.extend(b"\x00\x05")
        response.extend(b"\x04")
        response.extend(b"0001")

        self.assertEqual(_mod._parse_dns_response_code(bytes(response)), 0)
        self.assertEqual(_mod._parse_first_txt_answer(bytes(response)), "0001")


class TestListenerSourceGate(unittest.TestCase):
    def test_source_gate_rejects_legacy_parser(self) -> None:
        source = """
        let parts: Vec<&str> = ctrl.splitn(3, '-').collect();
        [b32data, ctrl, up] if up == "up" => {}
        [ctrl, dn] if dn == "dn" => {}
        """
        self.assertFalse(_mod._listener_source_supports_doh_grammar(source))

    def test_source_gate_accepts_doh_markers(self) -> None:
        source = """
        let ready = "rdy.";
        let uplink = ".u.";
        let downlink = ".d.";
        """
        self.assertTrue(_mod._listener_source_supports_doh_grammar(source))


class TestScenarioRun(unittest.TestCase):
    def test_run_skips_when_listener_source_is_legacy(self) -> None:
        ctx = _make_ctx()
        with patch.object(_mod, "_listener_source_supports_doh_grammar", return_value=False):
            with self.assertRaises(ScenarioSkipped) as cm:
                _mod.run(ctx)
        self.assertIn(_mod.LISTENER_DOH_BUG_ID, str(cm.exception))

    def test_upload_requires_nxdomain_per_chunk(self) -> None:
        with patch.object(_mod, "_chunk_packet", return_value=["abc", "def"]), \
             patch.object(_mod, "_send_dns_query", return_value=b"\x00\x01\x84\x03" + b"\x00" * 20):
            _mod._upload_packet_via_doh_grammar("127.0.0.1", 15353, "c2.test.local", b"payload", "session")

    def test_upload_raises_when_chunk_is_not_nxdomain(self) -> None:
        with patch.object(_mod, "_chunk_packet", return_value=["abc"]), \
             patch.object(_mod, "_send_dns_query", return_value=b"\x00\x01\x84\x00" + b"\x00" * 20):
            with self.assertRaises(AssertionError) as cm:
                _mod._upload_packet_via_doh_grammar(
                    "127.0.0.1", 15353, "c2.test.local", b"payload", "session"
                )
        self.assertIn("expected NXDOMAIN", str(cm.exception))

    def test_poll_ready_ignores_nxdomain_until_txt_arrives(self) -> None:
        responses = [
            b"\x00\x01\x84\x03" + b"\x00" * 20,
            None,
        ]

        def fake_send(*_args, **_kwargs):
            response = responses.pop(0)
            if response is not None:
                return response
            qname = "rdy.0011223344556677.d.c2.example.com"
            query = _mod._build_dns_txt_query(0x1234, qname)
            packet = bytearray()
            packet.extend(query[:2])
            packet.extend(b"\x84\x00")
            packet.extend(b"\x00\x01\x00\x01\x00\x00\x00\x00")
            packet.extend(query[12:])
            packet.extend(b"\xc0\x0c")
            packet.extend(b"\x00\x10\x00\x01")
            packet.extend(b"\x00\x00\x00\x00")
            packet.extend(b"\x00\x05")
            packet.extend(b"\x04")
            packet.extend(b"0002")
            return bytes(packet)

        with patch.object(_mod, "_send_dns_query", side_effect=fake_send), \
             patch("time.sleep"):
            total = _mod._poll_ready_via_doh_grammar(
                "127.0.0.1", 15353, "c2.test.local", "0011223344556677", timeout=1
            )

        self.assertEqual(total, 2)


if __name__ == "__main__":
    unittest.main()
