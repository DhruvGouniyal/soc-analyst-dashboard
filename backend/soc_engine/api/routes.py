"""
HTTP and WebSocket endpoints.

Two shapes only, both fixed by the dashboard client:

    GET /api/events?since=<epoch_ms>  ->  {"events": [...], "hosts": [...]}
    WS  /ws/events                    ->  {"type":"event","payload":{...}}
                                          {"type":"hosts","payload":[{...}]}
"""

from __future__ import annotations

import asyncio
import json
import logging
import time

from fastapi import APIRouter, Query, Request, WebSocket, WebSocketDisconnect

log = logging.getLogger(__name__)

router = APIRouter()


def event_frame(event: dict) -> str:
    return json.dumps({"type": "event", "payload": event}, separators=(",", ":"))


def hosts_frame(hosts: list[dict]) -> str:
    return json.dumps({"type": "hosts", "payload": hosts}, separators=(",", ":"))


@router.get("/api/events")
async def get_events(request: Request, since: int | None = Query(None, ge=0)) -> dict:
    """
    Historical snapshot. The client calls this once, with `since` set to 24
    hours ago, and never retries automatically — so a failure here is terminal
    until the analyst presses Retry.
    """
    engine = request.app.state.engine
    return {
        "events": engine.store.since(since, limit=engine.settings.query_limit),
        "hosts": engine.hosts.snapshot(),
    }


@router.get("/healthz")
async def healthz(request: Request) -> dict:
    """
    Diagnostics. `clients: 0` while the dashboard is open almost always means
    the HTTP GET is being blocked by CORS — the client only opens the WebSocket
    after the snapshot resolves.
    """
    engine = request.app.state.engine
    return {
        "ok": True,
        "events": len(engine.store),
        "clients": engine.manager.count,
        "droppedFrames": engine.manager.dropped,
        "authLogAvailable": engine.auth_collector.available,
        "ufwLogAvailable": engine.ufw_collector.available,
        "tailOffset": engine.auth_collector.offset,
        "lastLineTs": engine.auth_collector.last_ts_ms,
    }


@router.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    # No subprotocol: the browser client offers none, and responding with one
    # it did not request fails the handshake.
    await websocket.accept()

    engine = websocket.app.state.engine
    queue = engine.manager.connect(websocket)

    try:
        # Current inventory first, so a reconnecting dashboard does not sit on
        # stale host data until the next telemetry tick.
        await websocket.send_text(hosts_frame(engine.hosts.snapshot()))

        # Bounded replay closes the window between the HTTP snapshot and this
        # socket opening. Requires client-side dedupe by id; ships disabled
        # when ws_replay_seconds is 0.
        replay = engine.store.replay_window(
            int(time.time() * 1000),
            engine.settings.ws_replay_seconds,
            engine.settings.ws_replay_max,
        )
        for event in replay:
            await websocket.send_text(event_frame(event))

        writer = asyncio.create_task(_drain(websocket, queue))
        # The client never sends anything; this task exists purely to notice a
        # close. Without it a vanished client's queue would be filled forever.
        reader = asyncio.create_task(websocket.receive())

        done, pending = await asyncio.wait(
            {writer, reader}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        for task in done:
            exception = task.exception()
            if exception and not isinstance(exception, WebSocketDisconnect):
                log.debug("WebSocket task ended: %s", exception)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        log.exception("WebSocket handler failed")
    finally:
        engine.manager.disconnect(websocket)


async def _drain(websocket: WebSocket, queue: asyncio.Queue[str]) -> None:
    while True:
        frame = await queue.get()
        await websocket.send_text(frame)
