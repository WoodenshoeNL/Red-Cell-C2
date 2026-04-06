"""
Unit tests for :mod:`lib.kerberos_checks`.
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.kerberos_checks import (
    assert_klist_ticket_cache,
    assert_whoami_token_and_groups,
    client_principal_matches,
    klist_reports_zero_tickets,
    parse_klist_end_time,
    parse_klist_tickets,
    split_whoami_sections,
    token_section_contains_impersonation_level,
)


_SAMPLE_KLIST = """
Current LogonId is 0:0x3e7

Cached Tickets: (1)

#0>     Client: alice @ CONTOSO.COM
        Server: krbtgt/CONTOSO.COM @ CONTOSO.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Start Time: 4/1/2026 1:00:00 PM
        End Time:   4/1/2026 11:00:00 PM
        Renew Time: 4/8/2026 1:00:00 PM
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
"""

_SAMPLE_WHOAMI = """
USER INFORMATION
----------------

User Name: CONTOSO\\alice


GROUP INFORMATION
----------------

Group Name                             Type   SID ...
CONTOSO\\Domain Users                   Group  S-1-5-21-...
CONTOSO\\Domain Admins                  Group  S-1-5-21-...


PRIVILEGES INFORMATION
----------------------

Privilege Name                State
SeDebugPrivilege              Enabled


TOKEN INFORMATION
-----------------

Impersonation Level:       Identification
"""


class TestSplitWhoamiSections(unittest.TestCase):
    def test_splits_standard_headers(self) -> None:
        sections = split_whoami_sections(_SAMPLE_WHOAMI)
        self.assertIn("USER INFORMATION", sections)
        self.assertIn("GROUP INFORMATION", sections)
        self.assertIn("TOKEN INFORMATION", sections)
        self.assertIn("Impersonation Level", sections["TOKEN INFORMATION"])
        self.assertIn("Domain Users", sections["GROUP INFORMATION"])


class TestParseKlist(unittest.TestCase):
    def test_parses_ticket_block(self) -> None:
        tickets = parse_klist_tickets(_SAMPLE_KLIST)
        self.assertEqual(len(tickets), 1)
        self.assertIn("alice", tickets[0].client_line.lower())
        self.assertIsNotNone(tickets[0].end_time_raw)

    def test_zero_cached_report(self) -> None:
        self.assertTrue(klist_reports_zero_tickets("Cached Tickets: (0)\n"))
        self.assertFalse(klist_reports_zero_tickets(_SAMPLE_KLIST))

    def test_parse_end_time_us(self) -> None:
        dt = parse_klist_end_time("4/1/2026 11:00:00 PM")
        self.assertIsNotNone(dt)
        assert dt is not None
        self.assertEqual(dt.year, 2026)

    def test_client_principal_matches(self) -> None:
        self.assertTrue(
            client_principal_matches(
                "Client: alice @ CONTOSO.COM",
                "alice",
                "CONTOSO.COM",
            )
        )
        self.assertFalse(
            client_principal_matches(
                "Client: bob @ CONTOSO.COM",
                "alice",
                "CONTOSO.COM",
            )
        )


class TestTokenSection(unittest.TestCase):
    def test_impersonation_level(self) -> None:
        self.assertTrue(
            token_section_contains_impersonation_level(
                "Impersonation Level:       Identification\n",
                "Identification",
            )
        )
        self.assertFalse(
            token_section_contains_impersonation_level(
                "Impersonation Level:       Identification\n",
                "Delegation",
            )
        )


class TestAssertKlistTicketCache(unittest.TestCase):
    def test_passes_for_matching_future_ticket(self) -> None:
        assert_klist_ticket_cache(
            _SAMPLE_KLIST,
            "alice",
            "CONTOSO.COM",
            now=datetime(2026, 4, 1, 14, 0, 0),
        )

    def test_fails_when_zero_cached(self) -> None:
        with self.assertRaises(AssertionError):
            assert_klist_ticket_cache(
                "Cached Tickets: (0)\n",
                "alice",
                "CONTOSO.COM",
            )


class TestAssertWhoami(unittest.TestCase):
    def test_passes_sample(self) -> None:
        assert_whoami_token_and_groups(
            _SAMPLE_WHOAMI,
            expected_impersonation_level="Identification",
            expected_group_substrings=["Domain Users", "CONTOSO"],
        )

    def test_fails_missing_group(self) -> None:
        with self.assertRaises(AssertionError):
            assert_whoami_token_and_groups(
                _SAMPLE_WHOAMI,
                expected_impersonation_level="Identification",
                expected_group_substrings=["Nonexistent Group XYZ"],
            )


if __name__ == "__main__":
    unittest.main()
