"""
Per-connection state for sshd's two-line invalid-user sequence.

sshd logs ``Invalid user bob from 1.2.3.4`` and then, for the same attempt on
the same pid, ``Failed password for invalid user bob from 1.2.3.4 port 5678``.
Emitting on both double-counts every guess. The Failed line is preferred (it
carries the source port), so the Invalid line is held here as a precursor and
only flushed if the session ends without one — which happens when the client
disconnects before submitting a password.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

# A precursor older than this can no longer belong to a live attempt; pids get
# reused and a stale entry would attach to the wrong session.
PRECURSOR_TTL_MS = 120_000
MAX_TRACKED_SESSIONS = 1024


@dataclass(frozen=True)
class InvalidUserPrecursor:
    ts_ms: int
    user: str
    src_ip: str
    src_port: int | None
    raw_line: str


class SessionTracker:
    """Bounded, TTL'd map of sshd pid to its pending invalid-user precursor."""

    def __init__(self) -> None:
        self._pending: OrderedDict[int, InvalidUserPrecursor] = OrderedDict()

    def remember(self, pid: int | None, precursor: InvalidUserPrecursor) -> None:
        if pid is None:
            return
        self._pending[pid] = precursor
        self._pending.move_to_end(pid)
        while len(self._pending) > MAX_TRACKED_SESSIONS:
            self._pending.popitem(last=False)

    def resolve(self, pid: int | None) -> InvalidUserPrecursor | None:
        """Consumes the precursor — the Failed line superseded it."""
        if pid is None:
            return None
        return self._pending.pop(pid, None)

    def take_if_unresolved(self, pid: int | None, now_ms: int) -> InvalidUserPrecursor | None:
        """
        Consumes and returns the precursor when a session ends without a Failed
        line, so the attempt is still reported.
        """
        if pid is None:
            return None
        precursor = self._pending.pop(pid, None)
        if precursor is None:
            return None
        if now_ms - precursor.ts_ms > PRECURSOR_TTL_MS:
            return None
        return precursor

    def expire(self, now_ms: int) -> list[InvalidUserPrecursor]:
        """Flushes precursors whose sessions never produced a closing line."""
        expired = [
            (pid, p) for pid, p in self._pending.items() if now_ms - p.ts_ms > PRECURSOR_TTL_MS
        ]
        for pid, _ in expired:
            self._pending.pop(pid, None)
        return [p for _, p in expired]
