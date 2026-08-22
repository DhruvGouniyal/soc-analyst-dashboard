"""
Host telemetry from psutil, plus optional new-connection observation.

The `network` state comes from two real signals, taking the worse of the two.
Throughput alone is not enough: a brute-force run opens hundreds of short TCP
sessions while moving almost no bytes, so a bytes-only reading would report
"normal" during the loudest moment on the dashboard.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from collections import OrderedDict
from typing import Callable

import psutil

from ..config import Settings
from ..ids import stable_event_id
from ..models import WireEvent, WireHost

log = logging.getLogger(__name__)

EventSink = Callable[[WireEvent], None]
HostSink = Callable[[list[WireHost]], None]

# Throughput thresholds, bytes/sec across all non-loopback interfaces.
_ELEVATED_BPS = 256 * 1024
_SATURATED_BPS = 2 * 1024 * 1024

# Established remote socket counts.
_ELEVATED_SOCKETS = 25
_SATURATED_SOCKETS = 100

_SEVERITY_ORDER = {"normal": 0, "elevated": 1, "saturated": 2}

# new_connection dedupe
_CONN_TTL_SECONDS = 3600
_CONN_CACHE_MAX = 4096
_CONN_RATE_LIMIT_PER_MIN = 10


def _os_pretty_name() -> str:
    """PRETTY_NAME from /etc/os-release, with a portable fallback."""
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    import platform

    return f"{platform.system()} {platform.release()}".strip() or "Unknown"


def _is_local(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    return ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast


class HostTelemetryCollector:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._last_counters: tuple[float, int] | None = None
        self._os_name = _os_pretty_name()
        # Real machine name unless explicitly overridden — reporting a label the
        # host does not actually have would be a small fabrication.
        self._hostname = settings.victim_hostname or socket.gethostname()
        # (remote_ip, local_port) -> first seen. Bounded and TTL'd.
        self._seen_connections: OrderedDict[tuple[str, int], float] = OrderedDict()
        self._emitted_this_minute = 0
        self._minute_started = time.time()
        # Prime the CPU sampler. The first call always returns 0.0, and using
        # interval=1 inside the loop would block the event loop for a second on
        # every tick.
        psutil.cpu_percent(interval=None)

    # ------------------------------------------------------------------ host
    def sample_host(self) -> WireHost:
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent
        network = self._network_state()

        return WireHost(
            id=self.settings.victim_host_id,
            hostname=self._hostname,
            ip=self.settings.victim_ip,
            os=self._os_name,
            role="victim",
            status="online",
            # Integers: the host table renders the value verbatim with a % sign.
            cpu=int(round(cpu)),
            memory=int(round(memory)),
            network=network,
            lastSeen=int(time.time() * 1000),
        )

    def _network_state(self) -> str:
        throughput = self._throughput_state()
        sockets = self._socket_pressure_state()
        return throughput if _SEVERITY_ORDER[throughput] >= _SEVERITY_ORDER[sockets] else sockets

    def _throughput_state(self) -> str:
        now = time.time()
        try:
            counters = psutil.net_io_counters(pernic=True)
        except Exception:  # noqa: BLE001 - platform variation
            return "normal"

        total = sum(
            nic.bytes_sent + nic.bytes_recv
            for name, nic in counters.items()
            if not name.lower().startswith(("lo", "loopback"))
        )

        previous = self._last_counters
        self._last_counters = (now, total)
        if previous is None:
            return "normal"

        elapsed = max(0.001, now - previous[0])
        rate = max(0, total - previous[1]) / elapsed
        if rate >= _SATURATED_BPS:
            return "saturated"
        if rate >= _ELEVATED_BPS:
            return "elevated"
        return "normal"

    def _socket_pressure_state(self) -> str:
        connections = self._remote_connections()
        count = len(connections)
        if count >= _SATURATED_SOCKETS:
            return "saturated"
        if count >= _ELEVATED_SOCKETS:
            return "elevated"
        return "normal"

    def _all_connections(self) -> list:
        try:
            return psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Some platforms restrict the socket table; degrade rather than die.
            return []
        except Exception:  # noqa: BLE001
            return []

    def _remote_connections(self) -> list:
        """Connections with a non-local peer, in either direction."""
        return [c for c in self._all_connections() if c.raddr and not _is_local(c.raddr.ip)]

    @staticmethod
    def _listening_ports(connections: list) -> set[int]:
        """Local ports currently accepting connections."""
        return {
            c.laddr.port
            for c in connections
            if c.status == psutil.CONN_LISTEN and c.laddr
        }

    def _inbound_connections(self) -> list:
        """
        Connections *to* one of our listening ports.

        The direction test is the listening-port set, not the connection state:
        an outbound socket is ESTABLISHED with a remote address too, so filtering
        on state alone reports every website the host talks to. On a workstation
        that buries the actual security events under browser traffic.
        """
        connections = self._all_connections()
        listening = self._listening_ports(connections)
        return [
            c
            for c in connections
            if c.raddr
            and c.laddr
            and c.laddr.port in listening
            and c.status in ("ESTABLISHED", "SYN_RECV")
            and not _is_local(c.raddr.ip)
        ]

    # -------------------------------------------------------- new_connection
    def sample_new_connections(self, sink: EventSink) -> None:
        """
        Emits `new_connection` for previously unseen inbound peers.

        This is a SAMPLE of the socket table, not a flow record — connections
        shorter than the polling interval are invisible. That limitation is
        stated in the event detail rather than papered over.
        """
        if not self.settings.enable_new_connection:
            return

        now = time.time()
        if now - self._minute_started >= 60:
            self._minute_started = now
            self._emitted_this_minute = 0

        self._expire_connections(now)

        for conn in self._inbound_connections():
            if self._emitted_this_minute >= _CONN_RATE_LIMIT_PER_MIN:
                return

            key = (conn.raddr.ip, conn.laddr.port)
            if key in self._seen_connections:
                continue

            self._seen_connections[key] = now
            while len(self._seen_connections) > _CONN_CACHE_MAX:
                self._seen_connections.popitem(last=False)

            self._emitted_this_minute += 1
            ts_ms = int(now * 1000)
            sink(
                WireEvent(
                    id=stable_event_id(
                        ts_ms, "new_connection", conn.raddr.ip, extra=str(conn.laddr.port)
                    ),
                    timestamp=ts_ms,
                    severity="low",
                    eventType="new_connection",
                    sourceIp=conn.raddr.ip,
                    sourcePort=conn.raddr.port or None,
                    destinationIp=self.settings.victim_ip,
                    destinationPort=conn.laddr.port,
                    protocol="TCP",
                    host=self.settings.victim_host_id,
                    description=f"New inbound connection to port {conn.laddr.port}",
                    detail=(
                        f"First observed connection from {conn.raddr.ip} to local port "
                        f"{conn.laddr.port}. Derived from periodic socket-table sampling, so "
                        "connections shorter than the sampling interval are not represented."
                    ),
                    status="new",
                    mitreTechnique="T1071",
                    confidence=50,
                    logSource="netflow",
                )
            )

    def _expire_connections(self, now: float) -> None:
        stale = [key for key, seen in self._seen_connections.items() if now - seen > _CONN_TTL_SECONDS]
        for key in stale:
            self._seen_connections.pop(key, None)
