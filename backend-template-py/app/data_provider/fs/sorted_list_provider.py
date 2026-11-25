"""
===============================================
TXT FILE -> DISK SEARCHABLE LIST PROVIDER
===============================================
"""

from __future__ import annotations

import os
import threading
import time
from array import array
from dataclasses import dataclass
from typing import AsyncGenerator, Callable, Optional

from app.data_provider.list_provider import ListProvider, list_providers


@dataclass
class FsSortedListProviderOptions:
    #: Path to a file with one entry per line, sorted ascending (byte order).
    #: Use scripts/build_lists.py to produce it.
    file_path: str
    #: Normalize both stored entries and lookup values before comparing.
    #: Must match whatever normalize function was used to build the file.
    normalize: Optional[Callable[[str], str]] = None
    #: Re-check the file's mtime for changes at most this often (ms). Default 30s.
    reload_check_interval_ms: Optional[int] = None


class FsSortedListProvider(ListProvider):
    """
    Membership check against a large, sorted, newline-delimited file, without
    loading the file's contents into memory.

    Only a numeric offset index is kept in memory (one 64-bit integer per line).
    Each ``has()`` call does an on-disk binary search, reading only the handful
    of lines it actually needs to compare against - O(log n) reads instead of
    O(n).

    Requires a filesystem, so it targets environments where that's available:
    local dev, containers, traditional servers.  For fs-less runtimes implement
    ``ListProvider`` against KV/DB/HTTP and register it under a different
    factory type - none of the call sites using ``ListProvider`` need to change.
    """

    def __init__(self, name: str, options: FsSortedListProviderOptions) -> None:
        self.name = name
        self.options = options
        self._fd: Optional[int] = None
        self._offsets: Optional[array] = None  # start byte offset of each line
        self._file_size = 0
        self._mtime_ns = 0
        self._last_check = 0.0
        self._lock = threading.Lock()
        self._normalize = options.normalize or (lambda v: v.lower())
        self._reload_check_interval_ms = (
            options.reload_check_interval_ms
            if options.reload_check_interval_ms is not None
            else 30_000
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def values(self) -> AsyncGenerator[str, None]:
        """
        Iterate over every value in the file, in sorted order.  Streams
        line-by-line rather than loading the whole file into memory.

            async for value in provider.values(): ...
        """
        self._ensure_index()
        assert self._offsets is not None

        for i in range(len(self._offsets)):
            yield self._read_line(i)

    async def has(self, value: str) -> bool:
        return self.has_sync(value)

    def has_sync(self, value: str) -> bool:
        self._ensure_index()
        assert self._offsets is not None

        offsets = self._offsets
        target = self._normalize(value)

        lo = 0
        hi = len(offsets) - 1

        while lo <= hi:
            mid = (lo + hi) >> 1
            line = self._read_line(mid)

            if line == target:
                return True

            if line < target:
                lo = mid + 1
            else:
                hi = mid - 1

        return False

    async def dispose(self) -> None:
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)

            self._fd = None
            self._offsets = None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _read_line(self, index: int) -> str:
        offsets = self._offsets
        assert offsets is not None and self._fd is not None

        start = offsets[index]
        end = offsets[index + 1] if index + 1 < len(offsets) else self._file_size
        length = end - start

        buffer = os.pread(self._fd, length, start)

        text = buffer.decode("utf-8", errors="replace")

        if text.endswith("\n"):
            text = text[:-1]

        if text.endswith("\r"):
            text = text[:-1]

        return self._normalize(text)

    def _ensure_index(self) -> None:
        now = time.time() * 1000

        if self._offsets is not None and now - self._last_check < self._reload_check_interval_ms:
            return

        self._last_check = now

        stats = os.stat(self.options.file_path)

        if self._offsets is not None and stats.st_mtime_ns == self._mtime_ns:
            return  # unchanged since last build

        with self._lock:
            self._build_index(stats.st_mtime_ns, stats.st_size)

    def _build_index(self, mtime_ns: int, file_size: int) -> None:
        previous_fd = self._fd
        fd = os.open(self.options.file_path, os.O_RDONLY)

        # Stream the file once to record each line's starting byte offset.  We
        # only ever keep numbers, never the line contents, so this stays cheap
        # even for files with tens of millions of entries.
        offsets = array("Q")
        chunk_size = 1 << 20  # 1MB
        file_pos = 0
        at_line_start = True

        while True:
            chunk = os.pread(fd, chunk_size, file_pos)

            if not chunk:
                break

            i = 0
            length = len(chunk)

            while i < length:
                if at_line_start:
                    offsets.append(file_pos + i)
                    at_line_start = False

                newline = chunk.find(b"\n", i)

                if newline == -1:
                    break

                at_line_start = True
                i = newline + 1

            file_pos += length

        # Drop a trailing empty "line" caused by a final newline at EOF.
        if len(offsets) > 0 and offsets[-1] >= file_size:
            offsets.pop()

        self._fd = fd
        self._offsets = offsets
        self._file_size = file_size
        self._mtime_ns = mtime_ns

        if previous_fd is not None:
            os.close(previous_fd)


list_providers.register_factory(
    "fs-sorted",
    lambda name, options: FsSortedListProvider(name, options),
)


def create_sorted_list(
    name: str,
    options: FsSortedListProviderOptions,
) -> FsSortedListProvider:
    provider = list_providers.create("fs-sorted", name, options)
    assert isinstance(provider, FsSortedListProvider)
    return provider
