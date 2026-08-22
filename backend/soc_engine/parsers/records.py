"""
Parser output: a neutral record, before any detection logic runs.

Keeping parsing and detection separate means the correlators can be unit
tested against synthetic records without touching a log file, and the same
parse path serves both the historical backfill and the live tail.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AuthKind(str, Enum):
    """What an auth.log line represents."""

    FAILED_PASSWORD = "failed_password"
    FAILED_INVALID_USER = "failed_invalid_user"
    INVALID_USER = "invalid_user"          # precursor only — never emitted directly
    ACCEPTED = "accepted"
    MAX_AUTH_EXCEEDED = "max_auth_exceeded"
    SESSION_ABORTED = "session_aborted"    # closes an unresolved invalid-user precursor
    SUDO_BAD_PASSWORD = "sudo_bad_password"
    SUDO_NOT_SUDOER = "sudo_not_sudoer"
    SU_FAILED = "su_failed"


@dataclass(frozen=True)
class AuthRecord:
    ts_ms: int
    kind: AuthKind
    raw_line: str
    user: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    pid: int | None = None
    method: str | None = None
    # sudo "N incorrect password attempts"
    attempt_count: int | None = None
    # su "FAILED SU (to <target>)"
    target_user: str | None = None


@dataclass(frozen=True)
class UfwBlockRecord:
    """One [UFW BLOCK] line from kern.log."""

    ts_ms: int
    raw_line: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None
    dst_port: int | None
