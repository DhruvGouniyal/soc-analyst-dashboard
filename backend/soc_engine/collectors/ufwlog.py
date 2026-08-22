"""
kern.log collector for ``[UFW BLOCK]`` records, which back port-scan detection.

Disables itself cleanly when the file is absent or unreadable — a host without
ufw logging simply produces no port_scan events, rather than the engine
inventing them.
"""

from __future__ import annotations

import logging
import time
from typing import Callable

from ..config import Settings
from ..detect.pipeline import DetectionPipeline
from ..models import WireEvent
from ..parsers.ufw import parse_ufw_line
from .logtail import LogTailer, file_size, readable

log = logging.getLogger(__name__)

EventSink = Callable[[WireEvent], None]


class UfwLogCollector:
    def __init__(self, settings: Settings, pipeline: DetectionPipeline) -> None:
        self.settings = settings
        self.pipeline = pipeline
        self._tailer: LogTailer | None = None
        self.available = settings.enable_ufw_collector and readable(settings.kern_log_path)
        if settings.enable_ufw_collector and not self.available:
            log.warning(
                "kern.log not readable at %s — port scan detection disabled. "
                "Run 'sudo ufw logging on' and ensure the service user is in the 'adm' group.",
                settings.kern_log_path,
            )

    def backfill(self, sink: EventSink) -> int:
        if not self.available:
            return 0

        path = self.settings.kern_log_path
        start_offset = file_size(path)
        cutoff_ms = int(time.time() * 1000) - self.settings.backfill_window_seconds * 1000

        emitted = 0
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    record = parse_ufw_line(line)
                    if record is None or record.ts_ms < cutoff_ms:
                        continue
                    for event in self.pipeline.feed_ufw(record):
                        sink(event)
                        emitted += 1
        except OSError as error:
            log.warning("Could not read %s: %s", path, error)
            return 0

        log.info("Backfilled %d port scan events from %s", emitted, path)
        return start_offset

    async def run(self, start_offset: int, sink: EventSink) -> None:
        if not self.available:
            return

        self._tailer = LogTailer(
            self.settings.kern_log_path,
            start_offset=start_offset,
            poll_seconds=self.settings.tail_poll_seconds,
        )
        log.info("Tailing %s from offset %d", self.settings.kern_log_path, start_offset)

        async for line in self._tailer.lines():
            record = parse_ufw_line(line)
            if record is None:
                continue
            for event in self.pipeline.feed_ufw(record):
                sink(event)

    def stop(self) -> None:
        if self._tailer:
            self._tailer.stop()
