"""
Source-contract tests for the Specter/Archon DoH query grammar.

These tests intentionally read the current agent source files so the autotest
helpers fail loudly if the agent-side DoH query format changes and the harness
is not updated alongside it.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


REPO_ROOT = Path(__file__).resolve().parents[2]
SPECTER_DOH = REPO_ROOT / "agent" / "specter" / "src" / "doh_transport.rs"
ARCHON_DOH = REPO_ROOT / "agent" / "archon" / "src" / "core" / "TransportDoH.c"


class TestSpecterDohSourceContract(unittest.TestCase):
    def test_specter_source_documents_expected_uplink_format(self) -> None:
        text = SPECTER_DOH.read_text(encoding="utf-8")
        self.assertIn("<base32_chunk>.<seq:04x><total:04x>.<session_hex16>.u.<c2_domain>", text)

    def test_specter_source_documents_expected_ready_format(self) -> None:
        text = SPECTER_DOH.read_text(encoding="utf-8")
        self.assertIn("rdy.<session_hex16>.d.<c2_domain>", text)

    def test_specter_source_documents_expected_downlink_format(self) -> None:
        text = SPECTER_DOH.read_text(encoding="utf-8")
        self.assertIn("<seq:04x>.<session_hex16>.d.<c2_domain>", text)


class TestArchonDohSourceContract(unittest.TestCase):
    def test_archon_source_documents_expected_uplink_format(self) -> None:
        text = ARCHON_DOH.read_text(encoding="utf-8")
        self.assertIn("<base32_chunk>.<seq:04x><total:04x>.<session>.u.<c2_domain>", text)

    def test_archon_source_documents_expected_ready_format(self) -> None:
        text = ARCHON_DOH.read_text(encoding="utf-8")
        self.assertIn("Format: rdy.<session>.d.<c2_domain>", text)

    def test_archon_source_documents_expected_downlink_format(self) -> None:
        text = ARCHON_DOH.read_text(encoding="utf-8")
        self.assertIn("Format: <seq:04x>.<session>.d.<c2_domain>", text)


if __name__ == "__main__":
    unittest.main()
