"""
WebSocket fan-out.

Each client gets its own bounded queue and a dedicated writer task, so one slow
or stalled consumer can never block the detection path. `broadcast` is
synchronous and never awaits — it is called from the log-tailing coroutine, and
awaiting a client there would stall ingestion behind the network.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import WebSocket

log = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self, queue_size: int = 500) -> None:
        self.queue_size = queue_size
        self._clients: dict[WebSocket, asyncio.Queue[str]] = {}
        self._dropped = 0

    def connect(self, websocket: WebSocket) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=self.queue_size)
        self._clients[websocket] = queue
        return queue

    def disconnect(self, websocket: WebSocket) -> None:
        self._clients.pop(websocket, None)

    def broadcast(self, frame: str) -> None:
        """
        Queues a pre-serialized frame for every client.

        On overflow the OLDEST frame is dropped rather than the newest, and the
        socket is left open: a client that briefly stalls should miss a little
        history, not be disconnected mid-incident.
        """
        for queue in self._clients.values():
            if queue.full():
                try:
                    queue.get_nowait()
                    self._dropped += 1
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(frame)
            except asyncio.QueueFull:
                self._dropped += 1

    @property
    def count(self) -> int:
        return len(self._clients)

    @property
    def dropped(self) -> int:
        return self._dropped
