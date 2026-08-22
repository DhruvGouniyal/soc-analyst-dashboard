"""
SSH brute-force correlation.

A sliding window per source IP: N weighted failures inside T seconds fires one
critical event, then a cooldown suppresses re-firing until the burst is over.
Without the cooldown a 400-attempt hydra run would emit ~396 identical critical
alerts and bury the feed.

Every method takes the timestamp explicitly and NEVER calls time.time(). During
the historical backfill the clock must be the log line's own timestamp;
using wall-clock there makes 24 hours of failures look simultaneous, collapsing
them into a single window and producing zero historical brute-force events.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class BruteForceConfig:
    window_seconds: int = 60
    threshold: int = 5
    cooldown_seconds: int = 300
    max_tracked_ips: int = 10_000


@dataclass(frozen=True)
class BurstInfo:
    ip: str
    attempts: int
    span_seconds: float
    top_users: list[tuple[str, int]]


class SlidingWindowCorrelator:
    """Tracks failures per source IP and reports qualifying bursts."""

    def __init__(self, config: BruteForceConfig | None = None) -> None:
        self.config = config or BruteForceConfig()
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._users: dict[str, Counter[str]] = defaultdict(Counter)
        self._last_fired: dict[str, float] = {}

    def record_failure(
        self, ip: str, ts_seconds: float, user: str | None = None, weight: int = 1
    ) -> BurstInfo | None:
        """
        Records one failed attempt. Returns burst details when the threshold is
        crossed and the cooldown has elapsed, otherwise None.

        `weight` lets a single line stand for several attempts — sshd only logs
        "maximum authentication attempts exceeded" after MaxAuthTries (6 by
        default) guesses, so counting it as one would under-report badly.
        """
        window = self._failures[ip]
        for _ in range(max(1, weight)):
            window.append(ts_seconds)
        if user:
            self._users[ip][user] += 1

        cutoff = ts_seconds - self.config.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

        if len(self._failures) > self.config.max_tracked_ips:
            self._evict_oldest()

        if len(window) < self.config.threshold:
            return None

        last_fired = self._last_fired.get(ip, float("-inf"))
        if ts_seconds - last_fired < self.config.cooldown_seconds:
            return None

        self._last_fired[ip] = ts_seconds
        return BurstInfo(
            ip=ip,
            attempts=len(window),
            span_seconds=ts_seconds - window[0],
            top_users=self._users[ip].most_common(5),
        )

    def recent_failures(self, ip: str, ts_seconds: float, lookback_seconds: int) -> int:
        """
        Read-only count of failures in a wider window, used to escalate a
        successful login that follows a run of failures. Does not mutate state.
        """
        window = self._failures.get(ip)
        if not window:
            return 0
        cutoff = ts_seconds - lookback_seconds
        return sum(1 for t in window if t >= cutoff)

    def reset(self, ip: str) -> None:
        """Clears an IP's history — called after a successful authentication."""
        self._failures.pop(ip, None)
        self._users.pop(ip, None)

    def sweep(self, now_seconds: float) -> None:
        """Drops IPs whose windows are empty and whose cooldown is long past."""
        horizon = 2 * self.config.cooldown_seconds
        stale = [
            ip
            for ip, window in self._failures.items()
            if not window and now_seconds - self._last_fired.get(ip, 0.0) > horizon
        ]
        for ip in stale:
            self._failures.pop(ip, None)
            self._users.pop(ip, None)
            self._last_fired.pop(ip, None)

    def _evict_oldest(self) -> None:
        """Bounds memory when a spoofed-source flood invents thousands of IPs."""
        oldest_ip = min(
            self._failures,
            key=lambda ip: self._failures[ip][-1] if self._failures[ip] else 0.0,
        )
        self._failures.pop(oldest_ip, None)
        self._users.pop(oldest_ip, None)
        self._last_fired.pop(oldest_ip, None)
