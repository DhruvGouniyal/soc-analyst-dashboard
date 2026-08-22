"""
Current host inventory.

The dashboard replaces its whole host list from every `hosts` frame, so this
always publishes the complete set rather than a delta.
"""

from __future__ import annotations

from typing import Any

from ..models import WireHost


class HostRegistry:
    def __init__(self) -> None:
        self._hosts: dict[str, dict[str, Any]] = {}

    def update(self, host: WireHost) -> None:
        self._hosts[host.id] = host.model_dump(mode="json")

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self._hosts.values())
