"""
Bounded in-memory event store.

Capacity sits above the frontend's MAX_RETAINED_EVENTS (12 000) so a 24-hour
query is never truncated by the buffer before the time filter applies.
"""

from __future__ import annotations

from collections import deque
from typing import Any


class EventStore:
    def __init__(self, capacity: int = 20_000) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=capacity)

    def add(self, event: dict[str, Any]) -> None:
        """Appends in chronological order — backfill first, then live tail."""
        self._buffer.append(event)

    def extend(self, events: list[dict[str, Any]]) -> None:
        self._buffer.extend(events)

    def since(self, since_ms: int | None, limit: int = 5_000) -> list[dict[str, Any]]:
        """
        Events newer than `since_ms`, oldest-first.

        Walks backwards so that hitting `limit` keeps the MOST RECENT events.
        Slicing from the front instead would return the oldest matches and the
        dashboard would open showing yesterday.
        """
        cutoff = since_ms or 0
        collected: list[dict[str, Any]] = []
        for event in reversed(self._buffer):
            if event["timestamp"] <= cutoff or len(collected) >= limit:
                break
            collected.append(event)
        collected.reverse()
        return collected

    def replay_window(self, now_ms: int, seconds: int, limit: int) -> list[dict[str, Any]]:
        """
        Recent events for the replay burst sent on WebSocket connect, closing
        the gap between the HTTP snapshot and the socket opening. Requires
        client-side dedupe by id — see the frontend eventStore.
        """
        if seconds <= 0 or limit <= 0:
            return []
        return self.since(now_ms - seconds * 1000, limit=limit)

    def __len__(self) -> int:
        return len(self._buffer)
