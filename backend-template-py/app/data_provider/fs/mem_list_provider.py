"""
===============================================
TXT FILE -> MEMORY LIST PROVIDER
===============================================
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Callable, Optional

from app.data_provider.list_provider import ListProvider, list_providers


@dataclass
class MemoryFileListProviderOptions:
    #: Path to a newline-delimited text file. Order doesn't matter, no sorting required.
    file_path: str
    normalize: Optional[Callable[[str], str]] = None
    #: Re-check the file's mtime for changes at most this often (ms). Default 3s.
    reload_check_interval_ms: Optional[int] = None


class MemoryFileListProvider(ListProvider):
    """
    Loads an entire newline-delimited list file into an in-memory set.

    Good fit for lists that should live in a plain .txt file (editable without a
    redeploy) but are small/medium enough that holding them fully in memory is
    fine - protected headers, allowed origins, feature flags, a few thousand
    entries at most.  For lists too large to comfortably hold in memory
    (blocked IPs/domains, etc), use FsSortedListProvider instead, which never
    loads the full list contents.
    """

    def __init__(self, name: str, options: MemoryFileListProviderOptions) -> None:
        self.name = name
        self.options = options
        # dict used as an insertion-ordered set (a JS Set keeps insertion order)
        self._set: Optional[dict[str, None]] = None
        self._mtime_ns = 0
        self._last_check = 0.0
        self._normalize = options.normalize or (lambda v: v.lower())
        self._reload_check_interval_ms = (
            options.reload_check_interval_ms
            if options.reload_check_interval_ms is not None
            else 3_000
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def has(self, value: str) -> bool:
        return self.has_sync(value)

    def has_sync(self, value: str) -> bool:
        self._ensure_loaded()
        assert self._set is not None
        return self._normalize(value) in self._set

    async def values(self) -> list[str]:
        return self.values_sync()

    def values_sync(self) -> list[str]:
        """
        Returns the full list as an array. Use sparingly - it forces the file to
        be fully loaded. Prefer ``has()`` for membership checks.
        """
        self._ensure_loaded()
        assert self._set is not None
        return list(self._set)

    async def size(self) -> int:
        self._ensure_loaded()
        assert self._set is not None
        return len(self._set)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> None:
        now = time.time() * 1000

        if self._set is not None and now - self._last_check < self._reload_check_interval_ms:
            return

        self._last_check = now

        stats = os.stat(self.options.file_path)

        if self._set is not None and stats.st_mtime_ns == self._mtime_ns:
            return  # unchanged since last load

        self._load(stats.st_mtime_ns)

    def _load(self, mtime_ns: int) -> None:
        with open(self.options.file_path, "r", encoding="utf-8") as handle:
            raw = handle.read()

        values: dict[str, None] = {}

        for line in raw.splitlines():
            trimmed = line.strip()

            if trimmed and not trimmed.startswith("#"):
                values[self._normalize(trimmed)] = None

        self._set = values
        self._mtime_ns = mtime_ns


# GENERAL METHOD TO CREATE THIS PROVIDER
list_providers.register_factory(
    "memory-file",
    lambda name, options: MemoryFileListProvider(name, options),
)


# PREFERRED METHOD TO CREATE THIS PROVIDER
def create_memory_list(
    name: str,
    options: MemoryFileListProviderOptions,
) -> MemoryFileListProvider:
    """
    Typed convenience wrapper around ``list_providers.create('memory-file', ...)``.
    Use this instead of the generic registry call when you need access to
    MemoryFileListProvider-specific methods like values()/size().
    """
    provider = list_providers.create("memory-file", name, options)
    assert isinstance(provider, MemoryFileListProvider)
    return provider
