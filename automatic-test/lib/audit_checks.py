"""
Audit log assertions for autotest scenarios.

Helpers verify ordering, completeness (minimum counts per action label),
operator attribution (API operator vs system actors such as ``teamserver``),
filter semantics (substring operator/action, agent id), and — when a REST
base URL is available — ``until`` date-range queries via ``GET /api/v1/audit``.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any


def parse_audit_ts(iso_ts: str) -> datetime:
    """Parse an RFC 3339 audit timestamp from the CLI into a timezone-aware UTC datetime."""
    s = iso_ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_agent_id_hex(aid: str | None) -> str | None:
    """Normalize an agent id string to 8 uppercase hex digits (teamserver API rules)."""
    if aid is None:
        return None
    s = str(aid).strip()
    if not s:
        return None
    hex_digits = s[2:] if s.lower().startswith("0x") else s
    try:
        value = int(hex_digits, 16)
    except ValueError:
        return None
    return f"{value & 0xFFFF_FFFF:08X}"


def audit_entry_signature(entry: dict[str, Any]) -> tuple[Any, ...]:
    """Stable tuple for multiset comparisons of CLI-shaped audit rows."""
    aid = entry.get("agent_id")
    if aid is not None and aid != "":
        aid_norm = normalize_agent_id_hex(str(aid))
        aid_key = aid_norm if aid_norm is not None else str(aid).upper()
    else:
        aid_key = None
    detail = entry.get("detail")
    if detail == "":
        detail = None
    rs = entry.get("result_status") or ""
    rs = str(rs).lower()
    return (
        entry.get("ts"),
        entry.get("operator"),
        entry.get("action"),
        aid_key,
        detail,
        rs,
    )


def multiset_signatures(entries: list[dict[str, Any]]) -> Counter[tuple[Any, ...]]:
    return Counter(audit_entry_signature(e) for e in entries)


def assert_multiset_equal(
    a: list[dict[str, Any]],
    b: list[dict[str, Any]],
    *,
    label: str,
) -> None:
    ca, cb = multiset_signatures(a), multiset_signatures(b)
    assert ca == cb, (
        f"{label}: filtered result multiset mismatch\n"
        f"  only in A: {sorted((ca - cb).elements())}\n"
        f"  only in B: {sorted((cb - ca).elements())}"
    )


def assert_newest_first_timestamp_order(entries: list[dict[str, Any]]) -> None:
    """API returns rows newest-first; assert timestamps are monotonically non-increasing."""
    if len(entries) < 2:
        return
    for i in range(len(entries) - 1):
        cur = parse_audit_ts(entries[i]["ts"])
        nxt = parse_audit_ts(entries[i + 1]["ts"])
        assert cur >= nxt, (
            f"audit log not in newest-first order at index {i}: "
            f"{entries[i]['ts']!r} precedes {entries[i + 1]['ts']!r} in time"
        )


def assert_minimum_action_counts(
    entries: list[dict[str, Any]],
    minimums: dict[str, int],
    *,
    action_counter: Counter[str] | None = None,
) -> None:
    counts = action_counter or Counter(e["action"] for e in entries)
    for action, need in minimums.items():
        got = counts.get(action, 0)
        assert got >= need, (
            f"audit completeness: expected at least {need} {action!r} rows, got {got}. "
            f"Counts: {dict(counts)}"
        )


def assert_operator_attribution(
    entries: list[dict[str, Any]],
    *,
    expected_operator: str,
    extra_allowed_actor_actions: set[tuple[str, str]] | None = None,
) -> None:
    """Assert each row's operator is either the expected API key actor or an allowed system actor."""

    allowed: set[tuple[str, str]] = set(extra_allowed_actor_actions or ())
    # Lifecycle events emitted by the teamserver on behalf of the system, not an operator.
    allowed.add(("teamserver", "agent.checkin"))
    allowed.add(("teamserver", "agent.registered"))
    allowed.add(("teamserver", "agent.dead"))

    for e in entries:
        op = (e.get("operator") or "").strip()
        act = e.get("action", "")
        assert op, f"audit entry missing operator: action={act!r} ts={e.get('ts')!r}"
        if (op, act) in allowed:
            continue
        assert op == expected_operator, (
            f"audit operator mismatch: expected {expected_operator!r} for operator actions, "
            f"got {op!r} (action={act!r}, ts={e.get('ts')!r})"
        )


def expected_subset_operator_substring(
    entries: list[dict[str, Any]],
    operator_substr: str,
) -> list[dict[str, Any]]:
    """Rows matching the SQL ``instr(actor, ?)`` substring semantics for the operator filter."""
    return [e for e in entries if operator_substr in (e.get("operator") or "")]


def expected_subset_action_substring(
    entries: list[dict[str, Any]],
    action_substr: str,
) -> list[dict[str, Any]]:
    """Rows matching the SQL ``instr(action, ?)`` substring semantics for the action filter."""
    return [e for e in entries if action_substr in e.get("action", "")]


def expected_subset_agent_id(
    entries: list[dict[str, Any]],
    agent_id: str,
) -> list[dict[str, Any]]:
    """Rows matching the persisted ``details.agent_id`` filter for the given agent."""
    canon = normalize_agent_id_hex(agent_id)
    assert canon is not None, f"invalid agent id for audit filter: {agent_id!r}"
    out: list[dict[str, Any]] = []
    for e in entries:
        raw = e.get("agent_id")
        if raw is None or raw == "":
            continue
        if normalize_agent_id_hex(str(raw)) == canon:
            out.append(e)
    return out


def expected_subset_until_window(
    entries: list[dict[str, Any]],
    *,
    until_ts: str,
) -> list[dict[str, Any]]:
    """Rows at or before *until_ts* (inclusive upper bound), matching server ``until`` filter."""
    until_dt = parse_audit_ts(until_ts)
    out: list[dict[str, Any]] = []
    for e in entries:
        if parse_audit_ts(e["ts"]) <= until_dt:
            out.append(e)
    return out


def api_item_to_cli_shape(item: dict[str, Any]) -> dict[str, Any]:
    """Map a raw ``GET /api/v1/audit`` JSON item to the CLI ``log list`` row shape."""
    command = item.get("command")
    target_kind = item.get("target_kind") or ""
    target_id = item.get("target_id")
    detail = command
    if detail is None and target_id:
        detail = f"{target_kind}:{target_id}"
    elif detail is None and target_kind:
        detail = target_kind

    rs = item.get("result_status")
    if hasattr(rs, "value"):
        rs = rs.value
    rs_str = str(rs) if rs is not None else ""

    aid = item.get("agent_id")
    if aid is not None and aid != "":
        aid = str(aid).upper()
    else:
        aid = None

    return {
        "ts": item["occurred_at"],
        "operator": item["actor"],
        "action": item["action"],
        "agent_id": aid,
        "detail": detail,
        "result_status": rs_str,
    }
