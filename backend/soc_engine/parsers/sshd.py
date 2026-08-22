"""
auth.log line parsing: sshd, sudo, and su.

Three decisions here are load-bearing, and each is a real bug if inverted:

1. ``pam_unix(sshd:auth): authentication failure`` and ``PAM N more
   authentication failures`` are IGNORED. sshd emits a pam_unix line before
   every ``Failed password`` and a summary line after a burst. Counting any of
   them inflates the failure count two- or three-fold and fires the brute-force
   correlator on a single mistyped password.

2. ``Invalid user`` is a PRECURSOR, not an event. sshd logs it and then logs
   ``Failed password for invalid user <u>`` for the same attempt on the same
   pid. Emitting both double-counts the attempt and shows two rows per guess.
   The Failed line wins because it carries the source port.

3. ``maximum authentication attempts exceeded`` maps to ssh_failed_auth at high
   severity, NOT to ssh_brute_force. Leaving the correlator as the sole
   producer of ssh_brute_force keeps one coherent dominant threat per source in
   the dashboard's attribution.
"""

from __future__ import annotations

import re

from .records import AuthKind, AuthRecord
from .syslog_ts import TIMESTAMP_PATTERN, parse_syslog_time, to_epoch_ms

# IPv4 and IPv6, kept deliberately loose — validating an address here would
# reject the malformed values a hostile client can produce, which we still want
# to see in the feed.
_IP = r"(?P<ip>[0-9a-fA-F:.]+)"

SYSLOG_LINE_RE = re.compile(
    rf"^(?P<ts>{TIMESTAMP_PATTERN})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)

RE_FAILED = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) "
    rf"from {_IP} port (?P<port>\d+)"
)

# \S* not \S+ : sshd logs an empty username when the client sends one.
RE_INVALID_USER = re.compile(rf"^Invalid user (?P<user>\S*) from {_IP}(?: port (?P<port>\d+))?")

RE_ACCEPTED = re.compile(
    r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam|none) for "
    rf"(?P<user>\S+) from {_IP} port (?P<port>\d+)"
)

RE_MAX_AUTH = re.compile(
    r"^error: maximum authentication attempts exceeded for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) "
    rf"from {_IP} port (?P<port>\d+)"
)

RE_SESSION_ABORT = re.compile(
    r"^(?:Connection closed by|Disconnected from) "
    r"(?:authenticating user |invalid user )?"
    rf"(?P<user>\S+) {_IP} port (?P<port>\d+)"
)

RE_SUDO_BAD_PASSWORD = re.compile(r"^\s*(?P<user>\S+)\s*:\s*(?P<count>\d+) incorrect password attempts?")
RE_SUDO_NOT_SUDOER = re.compile(r"^\s*(?P<user>\S+)\s*:\s*user NOT in sudoers")
RE_SU_FAILED = re.compile(r"^FAILED SU \(to (?P<target>\S+)\)\s+(?P<user>\S+)")

# Explicitly ignored. Listed rather than left to fall through so the intent is
# visible and a future reader does not "fix" the omission.
_IGNORED_PATTERNS = (
    re.compile(r"^pam_unix\("),
    re.compile(r"^PAM \d+ more authentication failures"),
    re.compile(r"^PAM service\(sshd\) ignoring"),
    re.compile(r"^Received disconnect"),
    re.compile(r"^Server listening on"),
    re.compile(r"^session (opened|closed) for user"),
)


def _int_or_none(value: str | None) -> int | None:
    return int(value) if value else None


def parse_auth_line(line: str, now=None) -> AuthRecord | None:
    """
    Parses one auth.log line into a neutral record.

    Returns None for lines that are not security-relevant — the overwhelming
    majority of the file.
    """
    header = SYSLOG_LINE_RE.match(line.rstrip("\n"))
    if not header:
        return None

    moment = parse_syslog_time(header.group("ts"), now)
    if moment is None:
        return None
    ts_ms = to_epoch_ms(moment)

    proc = header.group("proc")
    pid = _int_or_none(header.group("pid"))
    msg = header.group("msg")
    raw = line.rstrip("\n")

    if any(pattern.match(msg) for pattern in _IGNORED_PATTERNS):
        return None

    if proc.startswith("sshd"):
        return _parse_sshd(msg, ts_ms, pid, raw)
    if proc.startswith("sudo"):
        return _parse_sudo(msg, ts_ms, pid, raw)
    if proc.startswith("su"):
        match = RE_SU_FAILED.match(msg)
        if match:
            return AuthRecord(
                ts_ms=ts_ms,
                kind=AuthKind.SU_FAILED,
                raw_line=raw,
                user=match.group("user"),
                target_user=match.group("target"),
                pid=pid,
            )
    return None


def _parse_sshd(msg: str, ts_ms: int, pid: int | None, raw: str) -> AuthRecord | None:
    match = RE_FAILED.match(msg)
    if match:
        invalid = bool(match.group("invalid"))
        return AuthRecord(
            ts_ms=ts_ms,
            kind=AuthKind.FAILED_INVALID_USER if invalid else AuthKind.FAILED_PASSWORD,
            raw_line=raw,
            user=match.group("user"),
            src_ip=match.group("ip"),
            src_port=_int_or_none(match.group("port")),
            pid=pid,
            method=match.group("method"),
        )

    match = RE_MAX_AUTH.match(msg)
    if match:
        return AuthRecord(
            ts_ms=ts_ms,
            kind=AuthKind.MAX_AUTH_EXCEEDED,
            raw_line=raw,
            user=match.group("user"),
            src_ip=match.group("ip"),
            src_port=_int_or_none(match.group("port")),
            pid=pid,
        )

    match = RE_ACCEPTED.match(msg)
    if match:
        return AuthRecord(
            ts_ms=ts_ms,
            kind=AuthKind.ACCEPTED,
            raw_line=raw,
            user=match.group("user"),
            src_ip=match.group("ip"),
            src_port=_int_or_none(match.group("port")),
            pid=pid,
            method=match.group("method"),
        )

    match = RE_INVALID_USER.match(msg)
    if match:
        return AuthRecord(
            ts_ms=ts_ms,
            kind=AuthKind.INVALID_USER,
            raw_line=raw,
            user=match.group("user"),
            src_ip=match.group("ip"),
            src_port=_int_or_none(match.group("port")),
            pid=pid,
        )

    match = RE_SESSION_ABORT.match(msg)
    if match:
        return AuthRecord(
            ts_ms=ts_ms,
            kind=AuthKind.SESSION_ABORTED,
            raw_line=raw,
            user=match.group("user"),
            src_ip=match.group("ip"),
            src_port=_int_or_none(match.group("port")),
            pid=pid,
        )

    return None


def _parse_sudo(msg: str, ts_ms: int, pid: int | None, raw: str) -> AuthRecord | None:
    match = RE_SUDO_BAD_PASSWORD.match(msg)
    if match:
        return AuthRecord(
            ts_ms=ts_ms,
            kind=AuthKind.SUDO_BAD_PASSWORD,
            raw_line=raw,
            user=match.group("user"),
            attempt_count=int(match.group("count")),
            pid=pid,
        )

    match = RE_SUDO_NOT_SUDOER.match(msg)
    if match:
        return AuthRecord(
            ts_ms=ts_ms,
            kind=AuthKind.SUDO_NOT_SUDOER,
            raw_line=raw,
            user=match.group("user"),
            pid=pid,
        )

    return None
