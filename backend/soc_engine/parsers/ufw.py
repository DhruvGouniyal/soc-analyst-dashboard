"""
kern.log ``[UFW BLOCK]`` parsing.

With ``ufw logging on``, the kernel writes one line per dropped packet. A SYN
scan against a host with default-deny produces one line per probed port, which
is the only cheap way to see port scans without an IDS.

Example line::

    Aug 22 11:41:02 ubuntu-victim kernel: [12345.678901] [UFW BLOCK] IN=enp0s3 OUT=
    MAC=08:00:27:... SRC=192.168.56.106 DST=192.168.56.105 LEN=44 TOS=0x00 PREC=0x00
    TTL=42 ID=12345 PROTO=TCP SPT=53412 DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0
"""

from __future__ import annotations

import re

from .records import UfwBlockRecord
from .syslog_ts import TIMESTAMP_PATTERN, parse_syslog_time, to_epoch_ms

KERN_LINE_RE = re.compile(
    rf"^(?P<ts>{TIMESTAMP_PATTERN})\s+(?P<host>\S+)\s+kernel:\s*(?:\[[\d.\s]+\]\s*)?(?P<msg>.*)$"
)

# Fields appear as KEY=VALUE in a fixed order, but matching them individually is
# more robust than one long pattern — netfilter omits keys depending on protocol
# (ICMP has no SPT/DPT).
_BLOCK_MARKER = re.compile(r"\[UFW (?:BLOCK|LIMIT BLOCK)\]")
_SRC_RE = re.compile(r"\bSRC=(?P<v>\S+)")
_DST_RE = re.compile(r"\bDST=(?P<v>\S+)")
_PROTO_RE = re.compile(r"\bPROTO=(?P<v>\S+)")
_SPT_RE = re.compile(r"\bSPT=(?P<v>\d+)")
_DPT_RE = re.compile(r"\bDPT=(?P<v>\d+)")

# The dashboard's Protocol union. Anything else is reported as TCP, since the
# field is display-only and an unmapped value would just look broken.
_KNOWN_PROTOCOLS = {"TCP", "UDP", "ICMP"}


def parse_ufw_line(line: str, now=None) -> UfwBlockRecord | None:
    """Parses a kern.log line. Returns None unless it is a UFW block record."""
    header = KERN_LINE_RE.match(line.rstrip("\n"))
    if not header:
        return None

    msg = header.group("msg")
    if not _BLOCK_MARKER.search(msg):
        return None

    src = _SRC_RE.search(msg)
    dst = _DST_RE.search(msg)
    if not src or not dst:
        return None

    moment = parse_syslog_time(header.group("ts"), now)
    if moment is None:
        return None

    proto_match = _PROTO_RE.search(msg)
    protocol = (proto_match.group("v").upper() if proto_match else "TCP")
    if protocol not in _KNOWN_PROTOCOLS:
        protocol = "TCP"

    spt = _SPT_RE.search(msg)
    dpt = _DPT_RE.search(msg)

    return UfwBlockRecord(
        ts_ms=to_epoch_ms(moment),
        raw_line=line.rstrip("\n"),
        src_ip=src.group("v"),
        dst_ip=dst.group("v"),
        protocol=protocol,
        src_port=int(spt.group("v")) if spt else None,
        dst_port=int(dpt.group("v")) if dpt else None,
    )
