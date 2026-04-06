"""Unit tests for :mod:`lib.audit_checks`."""

from __future__ import annotations

import unittest

from lib.audit_checks import (
    api_item_to_cli_shape,
    assert_minimum_action_counts,
    assert_multiset_equal,
    assert_newest_first_timestamp_order,
    assert_operator_attribution,
    audit_entry_signature,
    expected_subset_action_substring,
    expected_subset_agent_id,
    expected_subset_operator_substring,
    expected_subset_until_window,
    multiset_signatures,
    normalize_agent_id_hex,
    parse_audit_ts,
)


class TestParseAuditTs(unittest.TestCase):
    def test_z_suffix_parses_utc(self) -> None:
        dt = parse_audit_ts("2026-04-06T12:00:00Z")
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.utcoffset().total_seconds(), 0)

    def test_offset_preserved(self) -> None:
        dt = parse_audit_ts("2026-04-06T12:00:00+00:00")
        self.assertEqual(dt.utcoffset().total_seconds(), 0)


class TestNormalizeAgentId(unittest.TestCase):
    def test_hex_string(self) -> None:
        self.assertEqual(normalize_agent_id_hex("deadbeef"), "DEADBEEF")

    def test_0x_prefix(self) -> None:
        self.assertEqual(normalize_agent_id_hex("0x10"), "00000010")

    def test_teamserver_parse_agent_id_filter_semantics(self) -> None:
        # "256" is hex 0x256, not decimal — matches teamserver unit tests.
        self.assertEqual(normalize_agent_id_hex("256"), "00000256")


class TestTimestampOrder(unittest.TestCase):
    def test_ok_newest_first(self) -> None:
        rows = [
            {"ts": "2026-01-02T00:00:00Z", "action": "a"},
            {"ts": "2026-01-01T00:00:00Z", "action": "b"},
        ]
        assert_newest_first_timestamp_order(rows)

    def test_fail_when_out_of_order(self) -> None:
        rows = [
            {"ts": "2026-01-01T00:00:00Z", "action": "a"},
            {"ts": "2026-01-02T00:00:00Z", "action": "b"},
        ]
        with self.assertRaises(AssertionError):
            assert_newest_first_timestamp_order(rows)


class TestMultiset(unittest.TestCase):
    def test_equal(self) -> None:
        a = [{"ts": "t1", "operator": "o", "action": "x", "agent_id": None, "detail": None, "result_status": "success"}]
        b = [dict(a[0])]
        assert_multiset_equal(a, b, label="self")

    def test_differ(self) -> None:
        a = [{"ts": "t1", "operator": "o", "action": "x", "agent_id": None, "detail": None, "result_status": "success"}]
        b = [{"ts": "t2", "operator": "o", "action": "x", "agent_id": None, "detail": None, "result_status": "success"}]
        with self.assertRaises(AssertionError):
            assert_multiset_equal(a, b, label="diff")


class TestMinimumCounts(unittest.TestCase):
    def test_pass(self) -> None:
        entries = [
            {"action": "listener.create"},
            {"action": "listener.create"},
            {"action": "agent.task"},
        ]
        assert_minimum_action_counts(entries, {"listener.create": 1, "agent.task": 1})

    def test_fail(self) -> None:
        entries = [{"action": "listener.create"}]
        with self.assertRaises(AssertionError):
            assert_minimum_action_counts(entries, {"agent.task": 1})


class TestOperatorAttribution(unittest.TestCase):
    def test_expected_and_teamserver_checkin(self) -> None:
        entries = [
            {"operator": "alice", "action": "listener.create", "ts": "t1"},
            {"operator": "teamserver", "action": "agent.checkin", "ts": "t2"},
        ]
        assert_operator_attribution(entries, expected_operator="alice")

    def test_wrong_operator(self) -> None:
        entries = [{"operator": "other", "action": "listener.create", "ts": "t1"}]
        with self.assertRaises(AssertionError):
            assert_operator_attribution(entries, expected_operator="alice")


class TestExpectedSubsets(unittest.TestCase):
    def test_operator_substring(self) -> None:
        full = [
            {"operator": "alice", "action": "a", "ts": "t"},
            {"operator": "bob", "action": "b", "ts": "t"},
        ]
        self.assertEqual(len(expected_subset_operator_substring(full, "ali")), 1)

    def test_action_substring(self) -> None:
        full = [
            {"operator": "o", "action": "agent.task", "ts": "t"},
            {"operator": "o", "action": "listener.create", "ts": "t"},
        ]
        self.assertEqual(len(expected_subset_action_substring(full, "agent.task")), 1)

    def test_agent_id(self) -> None:
        full = [
            {"operator": "o", "action": "a", "ts": "t", "agent_id": "DEADBEEF"},
            {"operator": "o", "action": "b", "ts": "t", "agent_id": None},
        ]
        sub = expected_subset_agent_id(full, "deadbeef")
        self.assertEqual(len(sub), 1)

    def test_until_window(self) -> None:
        full = [
            {"ts": "2026-01-01T10:00:00Z", "action": "a"},
            {"ts": "2026-01-03T10:00:00Z", "action": "b"},
        ]
        sub = expected_subset_until_window(full, until_ts="2026-01-02T00:00:00Z")
        self.assertEqual(len(sub), 1)


class TestApiItemToCliShape(unittest.TestCase):
    def test_maps_fields(self) -> None:
        item = {
            "occurred_at": "2026-01-01T00:00:00Z",
            "actor": "alice",
            "action": "agent.task",
            "target_kind": "agent",
            "target_id": "CAFE0001",
            "agent_id": "CAFE0001",
            "command": None,
            "result_status": "success",
        }
        row = api_item_to_cli_shape(item)
        self.assertEqual(row["ts"], item["occurred_at"])
        self.assertEqual(row["operator"], "alice")
        self.assertEqual(row["action"], "agent.task")
        self.assertEqual(row["agent_id"], "CAFE0001")


class TestMultisetSignatures(unittest.TestCase):
    def test_counter(self) -> None:
        entries = [
            {"ts": "t", "operator": "o", "action": "a", "agent_id": None, "detail": None, "result_status": "s"},
            {"ts": "t", "operator": "o", "action": "a", "agent_id": None, "detail": None, "result_status": "s"},
        ]
        c = multiset_signatures(entries)
        self.assertEqual(c[audit_entry_signature(entries[0])], 2)


if __name__ == "__main__":
    unittest.main()
