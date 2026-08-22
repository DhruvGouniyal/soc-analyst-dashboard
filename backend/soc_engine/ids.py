"""
Deterministic event identifiers.

Ids hash the *field tuple*, not the byte offset in the log. Offsets change
after rotation, so an offset-derived id would give an event one value when it
arrived live and a different one when re-derived by a later backfill — which
defeats the client-side dedupe and makes the same detection appear twice.

The tuple (second, type, source ip, source port, pid, user) is unique in
practice: two authentication attempts cannot share a source port *and* a pid
*and* a wall-clock second.
"""

from __future__ import annotations

import hashlib


def stable_event_id(
    ts_ms: int,
    event_type: str,
    src_ip: str,
    src_port: int | None = None,
    pid: int | None = None,
    user: str | None = None,
    extra: str | None = None,
) -> str:
    """Returns a stable, collision-resistant id. Always a string — never a
    number, which the client would discard in favour of a random value."""
    key = f"{ts_ms}|{event_type}|{src_ip}|{src_port}|{pid}|{user}|{extra}"
    return "evt-" + hashlib.blake2s(key.encode("utf-8"), digest_size=8).hexdigest()
