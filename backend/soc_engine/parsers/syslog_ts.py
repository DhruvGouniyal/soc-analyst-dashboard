"""
Syslog timestamp parsing.

Traditional syslog carries no year, so the year must be inferred. It is also
space-padded on single-digit days (``Aug  2 09:00:01`` has two spaces), which
breaks naive ``split()``-based parsing.

Newer rsyslog configurations emit RFC3339 instead, which needs no inference.
Both are accepted.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Tolerance for a victim clock running ahead of ours. Without it, a log line
# written a few seconds in the future would be pushed back a whole year.
_FUTURE_SKEW = timedelta(hours=24)

TRADITIONAL_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})$"
)

RFC3339_RE = re.compile(
    r"^(?P<y>\d{4})-(?P<mon>\d{2})-(?P<day>\d{2})T"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})(?:\.(?P<frac>\d+))?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})$"
)

# Matches either form, for use inside a larger line regex.
TIMESTAMP_PATTERN = (
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)


def infer_year(
    month: int, day: int, hour: int, minute: int, second: int, now: datetime
) -> datetime | None:
    """
    Resolves a year-less syslog timestamp against the current time.

    Tries the current year first, then the previous one, taking the first
    candidate that is not implausibly far in the future. This is what makes the
    December→January rollover work: parsing ``Dec 31 23:59:58`` on January 1st
    produces a candidate ~365 days ahead, which is rejected in favour of last
    year.

    Returns None when the date cannot exist in either year — Feb 29 written by
    a corrupt or forged log line, for example. The caller skips the line. This
    must never raise: an unparsable line is a normal occurrence in a file an
    attacker can write to, and a crash here would stop ingestion entirely.
    """
    valid: list[datetime] = []
    for year in (now.year, now.year - 1):
        try:
            candidate = datetime(year, month, day, hour, minute, second, tzinfo=now.tzinfo)
        except ValueError:
            # Feb 29 in a non-leap year — try the other candidate.
            continue
        if candidate <= now + _FUTURE_SKEW:
            return candidate
        valid.append(candidate)

    # Every candidate sits implausibly far ahead (a skewed clock). Prefer the
    # closest one over discarding the line.
    return min(valid, key=lambda c: c - now) if valid else None


def parse_syslog_time(raw: str, now: datetime | None = None) -> datetime | None:
    """Parses either timestamp form. Returns an aware datetime, or None."""
    reference = now or datetime.now().astimezone()

    rfc = RFC3339_RE.match(raw)
    if rfc:
        # fromisoformat handles the offset; normalise 'Z' which it rejects
        # before Python 3.11.
        text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None

    traditional = TRADITIONAL_RE.match(raw)
    if traditional:
        month = MONTHS.get(traditional.group("mon"))
        if month is None:
            return None
        return infer_year(
            month,
            int(traditional.group("day")),
            int(traditional.group("h")),
            int(traditional.group("m")),
            int(traditional.group("s")),
            reference,
        )

    return None


def to_epoch_ms(moment: datetime) -> int:
    """
    Epoch milliseconds, which is what the dashboard expects.

    The datetime must be timezone-aware; calling .timestamp() on a naive value
    silently reinterprets it as local time on some platforms and UTC on others.
    """
    if moment.tzinfo is None:
        moment = moment.astimezone()
    return int(moment.timestamp() * 1000)
