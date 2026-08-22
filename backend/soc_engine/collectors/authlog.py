"""
auth.log collector: 24-hour backfill, then a live tail.

The handoff order matters. The file size is recorded BEFORE the backfill reads
it, and the tailer then starts at exactly that offset. Reading to EOF and then
"starting at EOF" either re-reads or skips whatever was appended in between.
"""

from __future__ import annotations

import gzip
import logging
import os
import time
from typing import Callable

from ..config import Settings
from ..detect.pipeline import DetectionPipeline
from ..models import WireEvent
from ..parsers.sshd import parse_auth_line
from .logtail import LogTailer, file_size, readable

log = logging.getLogger(__name__)

EventSink = Callable[[WireEvent], None]


class AuthLogCollector:
    def __init__(self, settings: Settings, pipeline: DetectionPipeline) -> None:
        self.settings = settings
        self.pipeline = pipeline
        self._tailer: LogTailer | None = None
        self._last_ts_ms: int | None = None
        self.available = readable(settings.auth_log_path)

    # -------------------------------------------------------------- backfill
    def backfill(self, sink: EventSink) -> int:
        """
        Replays recent history through the same parser and pipeline the live
        tail uses, so the dashboard opens populated. Returns the byte offset the
        tailer should start from.
        """
        path = self.settings.auth_log_path
        if not self.available:
            log.warning("auth.log not readable at %s — collector disabled", path)
            return 0

        # Record the size first; this is the tailer's starting point.
        start_offset = file_size(path)
        cutoff_ms = int(time.time() * 1000) - self.settings.backfill_window_seconds * 1000

        emitted = 0
        for source in self._history_sources(path):
            emitted += self._replay(source, cutoff_ms, sink)

        log.info("Backfilled %d events from %s", emitted, path)
        return start_offset

    def _history_sources(self, path: str) -> list[str]:
        """
        Current log first, plus rotated files only if they might still be within
        the window. Ubuntu rotates weekly, so auth.log alone almost always
        covers 24h; the rotated files are a fallback, not the normal path.
        """
        sources = [path]
        for suffix in (".1", ".2.gz", ".1.gz"):
            candidate = f"{path}{suffix}"
            if os.path.isfile(candidate) and os.access(candidate, os.R_OK):
                sources.append(candidate)
        # Oldest first so the correlators see history in order.
        return list(reversed(sources))

    def _replay(self, path: str, cutoff_ms: int, sink: EventSink) -> int:
        opener = gzip.open if path.endswith(".gz") else open
        emitted = 0
        try:
            with opener(path, "rt", encoding="utf-8", errors="replace") as handle:  # type: ignore[operator]
                for line in handle:
                    record = parse_auth_line(line)
                    if record is None or record.ts_ms < cutoff_ms:
                        continue
                    self._last_ts_ms = record.ts_ms
                    for event in self.pipeline.feed_auth(record):
                        sink(event)
                        emitted += 1
        except OSError as error:
            log.warning("Could not read %s: %s", path, error)
        return emitted

    # ------------------------------------------------------------------ tail
    async def run(self, start_offset: int, sink: EventSink) -> None:
        """Tails the log, feeding every parsed record into the pipeline."""
        if not self.available:
            return

        self._tailer = LogTailer(
            self.settings.auth_log_path,
            start_offset=start_offset,
            poll_seconds=self.settings.tail_poll_seconds,
        )
        log.info("Tailing %s from offset %d", self.settings.auth_log_path, start_offset)

        async for line in self._tailer.lines():
            record = parse_auth_line(line)
            if record is None:
                continue
            self._last_ts_ms = record.ts_ms
            for event in self.pipeline.feed_auth(record):
                sink(event)

    def stop(self) -> None:
        if self._tailer:
            self._tailer.stop()

    @property
    def offset(self) -> int:
        return self._tailer.offset if self._tailer else 0

    @property
    def last_ts_ms(self) -> int | None:
        return self._last_ts_ms
