"""
Parse and validate Windows ``klist`` and ``whoami /all`` output for scenario 09.

All parsing is defensive (unknown layouts yield empty results) so callers can
surface clear assertion messages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

# whoami /all section headers use a line of dashes under the title.
_WHOAMI_SECTION: Final[re.Pattern[str]] = re.compile(
    r"^(?P<title>[A-Z][A-Z0-9 ]{2,})\s*\r?\n[-]{3,}\s*\r?\n",
    re.MULTILINE,
)

# Ticket index and fields often share one line: ``#0>     Client: alice @ REALM``.
_KLIST_TICKET_SPLIT: Final[re.Pattern[str]] = re.compile(r"(?m)^\s*#\d+>\s*")

_CLIENT_LINE: Final[re.Pattern[str]] = re.compile(
    r"^\s*Client(?:\s+Name)?:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)

_END_TIME_LINE: Final[re.Pattern[str]] = re.compile(
    r"^\s*End Time:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)

_CACHED_TICKETS_ZERO: Final[re.Pattern[str]] = re.compile(
    r"Cached Tickets:\s*\(\s*0\s*\)",
    re.IGNORECASE,
)

# Common ``klist`` / regional time formats (stdlib only — no dateutil).
_TIME_FORMATS: Final[tuple[str, ...]] = (
    "%m/%d/%Y %I:%M:%S %p",
    "%d/%m/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%d.%m.%Y %H:%M:%S",
)


@dataclass(frozen=True)
class KlistTicket:
    """One Kerberos ticket block as parsed from ``klist`` text."""

    client_line: str
    end_time_raw: str | None
    end_time: datetime | None


def split_whoami_sections(body: str) -> dict[str, str]:
    """Split ``whoami /all`` output into sections keyed by header title.

    Recognises sections that use a dashed underline after the header, which is
    the standard layout for ``whoami /all`` on current Windows releases.
    """

    if not body.strip():
        return {}
    matches = list(_WHOAMI_SECTION.finditer(body))
    out: dict[str, str] = {}
    for i, m in enumerate(matches):
        title = m.group("title").strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        out[title] = body[start:end].strip()
    return out


def parse_klist_tickets(klist_output: str) -> list[KlistTicket]:
    """Parse ``klist`` stdout into :class:`KlistTicket` rows (Windows layout).

    Expects ticket blocks introduced by ``#0>``, ``#1>``, … as produced by the
    built-in Windows ``klist`` command.
    """

    text = klist_output.strip()
    if not text:
        return []
    chunks = _KLIST_TICKET_SPLIT.split(text)
    if len(chunks) < 2:
        return []
    tickets: list[KlistTicket] = []
    for block in chunks[1:]:
        client_m = _CLIENT_LINE.search(block)
        end_m = _END_TIME_LINE.search(block)
        client_line = client_m.group(0).strip() if client_m else ""
        end_raw = end_m.group(1).strip() if end_m else None
        end_dt = parse_klist_end_time(end_raw) if end_raw else None
        if client_line:
            tickets.append(
                KlistTicket(
                    client_line=client_line,
                    end_time_raw=end_raw,
                    end_time=end_dt,
                )
            )
    return tickets


def parse_klist_end_time(value: str | None) -> datetime | None:
    """Parse the time string from a ``klist`` *End Time* line."""

    if value is None:
        return None
    s = value.strip()
    if not s:
        return None
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def klist_reports_zero_tickets(klist_output: str) -> bool:
    """Return True if ``klist`` explicitly reports an empty ticket cache."""

    if _CACHED_TICKETS_ZERO.search(klist_output):
        return True
    # Older / localized strings sometimes omit the parenthesised count.
    if re.search(r"Cached Tickets:\s*0\b", klist_output, re.IGNORECASE):
        return True
    return False


def client_principal_matches(
    client_line: str,
    account_name: str,
    domain_realm: str,
) -> bool:
    """Return True if *client_line* names the expected *account* @ *realm*."""

    m = re.search(
        r"Client(?:\s+Name)?:\s*(.+)$",
        client_line.strip(),
        flags=re.IGNORECASE,
    )
    if not m:
        return False
    principal = m.group(1).strip()
    if not principal:
        return False
    acc = account_name.strip().lower()
    realm = domain_realm.strip().lower()
    compact = re.sub(r"\s+", "", principal.lower())
    # ``alice@CONTOSO.COM`` or ``alice@CONTOSO.COM@CONTOSO.COM`` (dup realm suffix).
    if f"{acc}@{realm}" in compact:
        return True
    p = principal.lower()
    return acc in p and realm in p


def token_section_contains_impersonation_level(
    token_section: str,
    expected_level: str,
) -> bool:
    """Return True if *TOKEN INFORMATION* contains the expected impersonation level."""

    if not token_section.strip():
        return False
    needle = expected_level.strip()
    if not needle:
        return False
    # Typical line: ``Impersonation Level:       Identification``
    for line in token_section.splitlines():
        if "impersonation level" in line.lower() and needle.lower() in line.lower():
            return True
    return False


def group_section_contains_all(
    group_section: str,
    expected_substrings: list[str],
) -> bool:
    """Return True if every expected substring appears in the group section body."""

    blob = group_section
    for part in expected_substrings:
        p = part.strip()
        if not p:
            return False
        if p not in blob:
            return False
    return True


def assert_klist_ticket_cache(
    klist_output: str,
    account_name: str,
    domain_realm: str,
    *,
    now: datetime | None = None,
    clock_skew: timedelta | None = None,
) -> None:
    """Assert *klist* shows at least one valid ticket for *account* @ *realm* with future expiry.

    Raises:
        AssertionError: When expectations are not met.
    """

    if klist_reports_zero_tickets(klist_output):
        raise AssertionError(
            "klist reports zero cached tickets — expected at least one ticket "
            "for a domain-joined Kerberos scenario.\n"
            f"  Output (first 800 chars): {klist_output[:800]!r}"
        )
    tickets = parse_klist_tickets(klist_output)
    if not tickets:
        raise AssertionError(
            "could not parse any Kerberos ticket blocks from klist output "
            "(expected ``#0>`` … blocks with ``Client:`` lines).\n"
            f"  Output (first 1200 chars): {klist_output[:1200]!r}"
        )
    clock = now or datetime.now()
    skew = clock_skew if clock_skew is not None else timedelta(minutes=5)
    matched = False
    for t in tickets:
        if not client_principal_matches(t.client_line, account_name, domain_realm):
            continue
        matched = True
        if t.end_time is None:
            raise AssertionError(
                "ticket for expected principal has no parseable End Time — "
                f"check locale / klist format.\n  Block: {t.client_line!r}\n"
                f"  end_time_raw={t.end_time_raw!r}"
            )
        if t.end_time <= clock - skew:
            raise AssertionError(
                "expected Kerberos ticket End Time in the future (allowing clock skew); got "
                f"{t.end_time} (now={clock}, skew={skew}).\n  Raw: {t.end_time_raw!r}"
            )
        break
    if not matched:
        raise AssertionError(
            "no klist ticket Client line matches the expected principal "
            f"{account_name!r} @ {domain_realm!r}.\n"
            f"  Parsed client lines: {[x.client_line for x in tickets]!r}"
        )


def assert_whoami_token_and_groups(
    whoami_all_output: str,
    *,
    expected_impersonation_level: str,
    expected_group_substrings: list[str],
) -> None:
    """Assert *whoami /all* contains TOKEN INFORMATION and GROUP expectations."""

    sections = split_whoami_sections(whoami_all_output)
    token_sec = sections.get("TOKEN INFORMATION", "")
    if not token_sec:
        raise AssertionError(
            "whoami /all is missing a TOKEN INFORMATION section "
            "(section headers with dashed underlines).\n"
            f"  Known sections: {list(sections)!r}\n"
            f"  Output (first 600 chars): {whoami_all_output[:600]!r}"
        )
    if not token_section_contains_impersonation_level(
        token_sec, expected_impersonation_level
    ):
        raise AssertionError(
            "TOKEN INFORMATION does not list the expected impersonation level "
            f"{expected_impersonation_level!r}.\n"
            f"  Section excerpt: {token_sec[:800]!r}"
        )
    group_sec = sections.get("GROUP INFORMATION", "")
    if not group_sec:
        raise AssertionError(
            "whoami /all is missing GROUP INFORMATION — cannot verify domain groups.\n"
            f"  Known sections: {list(sections)!r}"
        )
    if not group_section_contains_all(group_sec, expected_group_substrings):
        raise AssertionError(
            "GROUP INFORMATION is missing one of the expected group markers "
            f"{expected_group_substrings!r}.\n"
            f"  Section excerpt: {group_sec[:1200]!r}"
        )
