"""
The wire contract gate.

Every event and host leaving this service passes through these models. The
dashboard's ``normalizeEvent`` is forgiving to a fault — a wrong type is not
rejected, it is silently replaced with a default that looks plausible. A
seconds-valued timestamp renders the whole dashboard in 1970; a missing
severity turns a critical brute force into "low" and the console reads calm
during an active attack.

So validation happens here, loudly, at the source.

Field names are camelCase on purpose. It violates PEP 8, and it removes any
possibility of shipping snake_case by accident: the client accepts snake_case
for exactly three fields (``event_type``, ``src_ip``, ``dest_ip``) and silently
defaults every other snake_case key.

These Literal types mirror ``src/types/security.ts`` exactly. If that file
changes, change these in the same commit.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low"]
Status = Literal["new", "investigating", "blocked", "resolved"]
Protocol = Literal["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SSH", "DNS"]
LogSource = Literal["auth.log", "syslog", "audit.log", "suricata", "netflow", "process"]
EventType = Literal[
    "ssh_brute_force",
    "ssh_failed_auth",
    "successful_login",
    "port_scan",
    "suspicious_login",
    "web_attack",
    "suspicious_process",
    "privilege_escalation",
    "data_exfiltration",
    "new_connection",
    "malware_signature",
]
HostRole = Literal["victim", "attacker", "sensor"]
HostStatus = Literal["online", "offline", "degraded"]
NetworkState = Literal["normal", "elevated", "saturated"]

# Epoch milliseconds for any plausible date are >1e12; epoch *seconds* are
# ~1.7e9. This bound is the cheapest possible guard against the single most
# damaging mistake in the integration.
_MIN_EPOCH_MS = 1_000_000_000_000


class WireEvent(BaseModel):
    """One detection, shaped exactly as the dashboard expects it."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    timestamp: int = Field(gt=_MIN_EPOCH_MS)
    # No default. The client does NOT fall back to the event catalog's
    # defaultSeverity — a missing severity silently becomes "low".
    severity: Severity
    eventType: EventType
    sourceIp: str
    sourcePort: int | None = None
    destinationIp: str
    destinationPort: int | None = None
    protocol: Protocol = "TCP"
    # Must equal an id in the hosts array, or the event joins to no host and
    # disappears from host risk and the host filter.
    host: str = "ubuntu-victim"
    description: str
    detail: str | None = None
    status: Status = "new"
    mitreTechnique: str | None = None
    confidence: float = Field(ge=0, le=100)
    logSource: LogSource = "auth.log"
    rawLog: str | None = None


class WireHost(BaseModel):
    """One monitored asset."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    hostname: str
    ip: str
    os: str
    role: HostRole = "victim"
    status: HostStatus = "online"
    # Integers, not floats: HostTable renders `{value}%` verbatim, so 23.4000001
    # would be shown in full.
    cpu: int = Field(ge=0, le=100)
    memory: int = Field(ge=0, le=100)
    network: NetworkState = "normal"
    lastSeen: int = Field(gt=_MIN_EPOCH_MS)
