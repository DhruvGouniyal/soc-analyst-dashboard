"""
Port-scan correlation over UFW block records.

Counts DISTINCT destination ports per source inside a window — not raw packet
count. A single closed port retried twenty times is a misconfigured client;
twenty different ports touched once each is a sweep. Only the second is a scan,
and only distinct-port counting tells them apart.

Like the brute-force correlator, this is driven entirely by the log line's own
timestamp so the backfill reproduces history faithfully.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class PortScanConfig:
    window_seconds: int = 60
    threshold: int = 10
    cooldown_seconds: int = 300
    max_tracked_ips: int = 10_000


@dataclass(frozen=True)
class ScanInfo:
    ip: str
    distinct_ports: int
    total_probes: int
    span_seconds: float
    sample_ports: list[int]


class PortScanCorrelator:
    def __init__(self, config: PortScanConfig | None = None) -> None:
        self.config = config or PortScanConfig()
        # (timestamp, port) pairs, so eviction and distinct-counting share one
        # structure.
        self._probes: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._last_fired: dict[str, float] = {}

    def record_block(self, ip: str, port: int | None, ts_seconds: float) -> ScanInfo | None:
        if port is None:
            # ICMP and malformed packets carry no port; they cannot evidence a
            # port sweep, so they are counted nowhere.
            return None

        window = self._probes[ip]
        window.append((ts_seconds, port))

        cutoff = ts_seconds - self.config.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

        if len(self._probes) > self.config.max_tracked_ips:
            self._evict_oldest()

        distinct = {p for _, p in window}
        if len(distinct) < self.config.threshold:
            return None

        last_fired = self._last_fired.get(ip, float("-inf"))
        if ts_seconds - last_fired < self.config.cooldown_seconds:
            return None

        self._last_fired[ip] = ts_seconds
        return ScanInfo(
            ip=ip,
            distinct_ports=len(distinct),
            total_probes=len(window),
            span_seconds=ts_seconds - window[0][0],
            sample_ports=sorted(distinct)[:8],
        )

    def sweep(self, now_seconds: float) -> None:
        horizon = 2 * self.config.cooldown_seconds
        stale = [
            ip
            for ip, window in self._probes.items()
            if not window and now_seconds - self._last_fired.get(ip, 0.0) > horizon
        ]
        for ip in stale:
            self._probes.pop(ip, None)
            self._last_fired.pop(ip, None)

    def _evict_oldest(self) -> None:
        oldest_ip = min(
            self._probes,
            key=lambda ip: self._probes[ip][-1][0] if self._probes[ip] else 0.0,
        )
        self._probes.pop(oldest_ip, None)
        self._last_fired.pop(oldest_ip, None)
