"""
Application assembly and lifecycle.

Startup order matters: backfill runs to completion BEFORE the tailers start, so
the correlators see history in chronological order and the dashboard's first
snapshot is already populated.

Run with exactly one worker. The event store, the correlators, and the client
set all live in this process; a second worker would hold a different history
and a different set of clients, so the dashboard would see a fraction of
reality depending on which worker answered.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.manager import ConnectionManager
from .api.routes import event_frame, hosts_frame, router
from .collectors.authlog import AuthLogCollector
from .collectors.telemetry import HostTelemetryCollector
from .collectors.ufwlog import UfwLogCollector
from .config import Settings, settings as default_settings
from .detect.pipeline import DetectionPipeline
from .models import WireEvent
from .store.hosts import HostRegistry
from .store.ring import EventStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("soc_engine")


class Engine:
    """Holds every long-lived component, reachable from routes via app.state."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.store = EventStore(capacity=settings.store_capacity)
        self.hosts = HostRegistry()
        self.manager = ConnectionManager(queue_size=settings.ws_queue_size)
        self.pipeline = DetectionPipeline(settings)
        self.auth_collector = AuthLogCollector(settings, self.pipeline)
        self.ufw_collector = UfwLogCollector(settings, self.pipeline)
        self.telemetry = HostTelemetryCollector(settings)
        self._tasks: list[asyncio.Task] = []

    # ------------------------------------------------------------- publishing
    def store_only(self, event: WireEvent) -> None:
        """Backfill sink: record history without broadcasting it."""
        self.store.add(event.model_dump(mode="json"))

    def publish(self, event: WireEvent) -> None:
        """
        Live sink. Synchronous by design — this runs inside the log-tailing
        coroutine, and awaiting a slow client here would stall ingestion.
        """
        payload = event.model_dump(mode="json")
        self.store.add(payload)
        self.manager.broadcast(event_frame(payload))

    def publish_hosts(self) -> None:
        self.manager.broadcast(hosts_frame(self.hosts.snapshot()))

    # ---------------------------------------------------------------- startup
    async def start(self) -> None:
        # 1. Seed host state so the very first HTTP snapshot has an inventory.
        self.hosts.update(self.telemetry.sample_host())

        # 2. Backfill, recording each collector's starting offset.
        auth_offset = self.auth_collector.backfill(self.store_only)
        ufw_offset = self.ufw_collector.backfill(self.store_only)
        log.info("Store holds %d events after backfill", len(self.store))

        # 3. Live tails, starting exactly where the backfill stopped reading.
        self._tasks = [
            asyncio.create_task(self.auth_collector.run(auth_offset, self.publish)),
            asyncio.create_task(self.ufw_collector.run(ufw_offset, self.publish)),
            asyncio.create_task(self._telemetry_loop()),
            asyncio.create_task(self._sweep_loop()),
        ]

    async def stop(self) -> None:
        self.auth_collector.stop()
        self.ufw_collector.stop()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

    # ------------------------------------------------------------------ loops
    async def _telemetry_loop(self) -> None:
        while True:
            try:
                self.hosts.update(self.telemetry.sample_host())
                self.publish_hosts()
                self.telemetry.sample_new_connections(self.publish)
            except Exception:  # noqa: BLE001 - telemetry must never kill the service
                log.exception("Telemetry sample failed")
            await asyncio.sleep(self.settings.telemetry_interval_seconds)

    async def _sweep_loop(self) -> None:
        """Periodic eviction so correlator state cannot grow without bound."""
        while True:
            await asyncio.sleep(60)
            try:
                self.pipeline.sweep(time.time())
            except Exception:  # noqa: BLE001
                log.exception("Correlator sweep failed")


def create_app(settings: Settings | None = None) -> FastAPI:
    active = settings or default_settings

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine = Engine(active)
        app.state.engine = engine
        await engine.start()
        log.info(
            "SOC engine ready — auth.log=%s ufw=%s victim=%s/%s",
            engine.auth_collector.available,
            engine.ufw_collector.available,
            active.victim_host_id,
            active.victim_ip,
        )
        try:
            yield
        finally:
            await engine.stop()

    app = FastAPI(title="SOC Detection Engine", version="1.0.0", lifespan=lifespan)

    # Without this the browser blocks the snapshot response, and because the
    # client only opens its WebSocket after that snapshot resolves, the symptom
    # is "no WebSocket connection" rather than an obvious CORS error.
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=active.cors_origin_regex,
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    app.include_router(router)
    return app


app = create_app()


__all__ = ["app", "create_app", "Engine"]
