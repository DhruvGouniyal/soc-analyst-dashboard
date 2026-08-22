"""
Rotation- and truncation-safe log tailing.

Polling rather than inotify: logrotate churns watch descriptors, and half a
second of latency is invisible on this dashboard. The four cases below are
handled in priority order, and getting the first one wrong silently loses the
last lines written before every rotation.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import AsyncIterator

log = logging.getLogger(__name__)

_READ_CHUNK = 1 << 16


class LogTailer:
    """
    Yields complete lines from a growing file.

    Never yields a partial line: a write can land mid-line, so trailing bytes
    without a newline are buffered until the rest arrives.
    """

    def __init__(self, path: str, start_offset: int = 0, poll_seconds: float = 0.5) -> None:
        self.path = path
        self.poll_seconds = poll_seconds
        self._handle = None
        self._position = start_offset
        self._identity: tuple[int, int] | None = None
        self._partial = ""
        self._stopped = False

    def stop(self) -> None:
        self._stopped = True

    # ------------------------------------------------------------------ open
    def _open(self, seek_to: int | None = None) -> bool:
        try:
            handle = open(self.path, "r", encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return False
        except PermissionError:
            log.error(
                "Permission denied reading %s — the service user needs the 'adm' group", self.path
            )
            return False

        stat = os.fstat(handle.fileno())
        self._identity = (stat.st_dev, stat.st_ino)
        target = stat.st_size if seek_to is None else min(seek_to, stat.st_size)
        handle.seek(target)
        self._position = target
        self._handle = handle
        return True

    def _drain(self) -> str:
        """Reads everything available from the current handle."""
        if self._handle is None:
            return ""
        chunks: list[str] = []
        while True:
            chunk = self._handle.read(_READ_CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
        text = "".join(chunks)
        if text:
            self._position = self._handle.tell()
        return text

    def _rotated(self) -> bool:
        """True when the path now points at a different file than our handle."""
        try:
            stat = os.stat(self.path)
        except FileNotFoundError:
            return False
        return self._identity is not None and (stat.st_dev, stat.st_ino) != self._identity

    def _truncated(self) -> bool:
        try:
            return os.stat(self.path).st_size < self._position
        except FileNotFoundError:
            return False

    # ------------------------------------------------------------------ read
    def _read_available(self) -> str:
        """
        One synchronous poll. Runs on a worker thread so a slow disk cannot
        stall the event loop.
        """
        if self._handle is None:
            if not self._open(seek_to=self._position):
                return ""

        # 1. Rotation. Drain the OLD handle to EOF first — those bytes are gone
        #    the moment we close it, and they are exactly the lines written just
        #    before logrotate moved the file.
        if self._rotated():
            tail_of_old = self._drain()
            try:
                self._handle.close()
            except OSError:
                pass
            self._handle = None
            self._position = 0
            self._open(seek_to=0)
            return tail_of_old + self._drain()

        # 2. Truncation (copytruncate, or `truncate -s 0`): same inode, smaller
        #    file. Start over from the top.
        if self._truncated():
            self._handle.seek(0)
            self._position = 0
            return self._drain()

        # 3. Normal growth.
        return self._drain()

    async def lines(self) -> AsyncIterator[str]:
        """Yields complete log lines forever, until stop() is called."""
        while not self._stopped:
            try:
                text = await asyncio.to_thread(self._read_available)
            except Exception:  # noqa: BLE001 - a tailer must never die
                log.exception("Error reading %s", self.path)
                text = ""

            if text:
                buffered = self._partial + text
                # 4. Partial line: keep anything after the final newline.
                *complete, self._partial = buffered.split("\n")
                for line in complete:
                    if line:
                        yield line

            await asyncio.sleep(self.poll_seconds)

    @property
    def offset(self) -> int:
        return self._position


def file_size(path: str) -> int:
    """Current size, or 0 when the file is absent."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def readable(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.R_OK)
